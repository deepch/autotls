package autotls

import (
	"crypto/tls"
	"net/http"

	"golang.org/x/crypto/acme/autocert"
)

// Run support 1-line LetsEncrypt HTTPS servers
func Run(r http.Handler, domain ...string) error {
	return http.Serve(autocert.NewListener(domain...), r)
}
type DevNull struct{}

func (DevNull) Write(p []byte) (int, error) {
	return len(p), nil
}
// RunWithManager support custom autocert manager
func RunWithManager(r http.Handler, m *autocert.Manager) error {
	l := log.New(new(DevNull), "", 0)
	s := &http.Server{
		Addr:      ":https",
		TLSConfig: &tls.Config{GetCertificate: m.GetCertificate},
		Handler:   r,
		ErrorLog: l,
	}
	s.SetKeepAlivesEnabled(false)
	return s.ListenAndServeTLS("", "")
}
