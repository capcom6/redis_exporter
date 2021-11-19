package exporter

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"

	"golang.org/x/crypto/bcrypt"
)

type Config struct {
	// TLSConfig  TLSStruct                     `yaml:"tls_server_config"`
	// HTTPConfig HTTPStruct                    `yaml:"http_server_config"`
	Users map[string]string `yaml:"basic_auth_users"`
}

func getConfig(configPath string) (*Config, error) {
	content, err := ioutil.ReadFile(configPath)
	if err != nil {
		return nil, err
	}
	c := &Config{
		// TLSConfig: TLSStruct{
		// 	MinVersion:               tls.VersionTLS12,
		// 	MaxVersion:               tls.VersionTLS13,
		// 	PreferServerCipherSuites: true,
		// },
		// HTTPConfig: HTTPStruct{HTTP2: true},
	}
	err = yaml.UnmarshalStrict(content, c)
	// if err == nil {
	// 	err = validateHeaderConfig(c.HTTPConfig.Header)
	// }
	// c.TLSConfig.SetDirectory(filepath.Dir(configPath))
	return c, err
}

func (e *Exporter) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if e.options.WebConfigFile == "" {
		e.mux.ServeHTTP(w, r)
		return
	}

	c, err := getConfig(e.options.WebConfigFile)
	if err != nil {
		log.Errorf("Unable to parse configuration")
		// u.logger.Log("msg", "Unable to parse configuration", "err", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	if len(c.Users) == 0 {
		e.mux.ServeHTTP(w, r)
		return
	}

	user, pass, auth := r.BasicAuth()

	if auth {
		hashedPassword, validUser := c.Users[user]

		if !validUser {
			// The user is not found. Use a fixed password hash to
			// prevent user enumeration by timing requests.
			// This is a bcrypt-hashed version of "fakepassword".
			hashedPassword = "$2y$10$QOauhQNbBCuQDKes6eFzPeMqBSjb7Mr5DUmpZ/VcEd00UAV/LDeSi"
		}

		e.bcryptMtx.Lock()
		err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(pass))
		e.bcryptMtx.Unlock()

		authOk := err == nil

		if authOk && validUser {
			e.mux.ServeHTTP(w, r)
			return
		}
	}

	w.Header().Set("WWW-Authenticate", "Basic")
	http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
}

func (e *Exporter) healthHandler(w http.ResponseWriter, r *http.Request) {
	_, _ = w.Write([]byte(`ok`))
}

func (e *Exporter) indexHandler(w http.ResponseWriter, r *http.Request) {
	_, _ = w.Write([]byte(`<html>
<head><title>Redis Exporter ` + e.buildInfo.Version + `</title></head>
<body>
<h1>Redis Exporter ` + e.buildInfo.Version + `</h1>
<p><a href='` + e.options.MetricsPath + `'>Metrics</a></p>
</body>
</html>
`))
}

func (e *Exporter) scrapeHandler(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("target")
	if target == "" {
		http.Error(w, "'target' parameter must be specified", http.StatusBadRequest)
		e.targetScrapeRequestErrors.Inc()
		return
	}

	if !strings.Contains(target, "://") {
		target = "redis://" + target
	}

	u, err := url.Parse(target)
	if err != nil {
		http.Error(w, fmt.Sprintf("Invalid 'target' parameter, parse err: %ck ", err), http.StatusBadRequest)
		e.targetScrapeRequestErrors.Inc()
		return
	}

	// get rid of username/password info in "target" so users don't send them in plain text via http
	u.User = nil
	target = u.String()

	opts := e.options

	if ck := r.URL.Query().Get("check-keys"); ck != "" {
		opts.CheckKeys = ck
	}

	if csk := r.URL.Query().Get("check-single-keys"); csk != "" {
		opts.CheckSingleKeys = csk
	}

	if cs := r.URL.Query().Get("check-streams"); cs != "" {
		opts.CheckStreams = cs
	}

	if css := r.URL.Query().Get("check-single-streams"); css != "" {
		opts.CheckSingleStreams = css
	}

	if cntk := r.URL.Query().Get("count-keys"); cntk != "" {
		opts.CountKeys = cntk
	}

	registry := prometheus.NewRegistry()
	opts.Registry = registry

	_, err = NewRedisExporter(target, opts)
	if err != nil {
		http.Error(w, "NewRedisExporter() err: err", http.StatusBadRequest)
		e.targetScrapeRequestErrors.Inc()
		return
	}

	promhttp.HandlerFor(
		registry, promhttp.HandlerOpts{ErrorHandling: promhttp.ContinueOnError},
	).ServeHTTP(w, r)
}
