package sshserver

import (
	"fmt"

	"github.com/prometheus/client_golang/prometheus"
)

// Login results, the values of the result label on gameplane_sftp_logins_total.
const (
	loginOK     = "ok"
	loginDenied = "denied" // the API refused the credentials or rate-limited them
	loginError  = "error"  // the API failed or was unreachable
	loginLimit  = "limit"  // the user already has the maximum number of connections
)

// Metrics holds the server's Prometheus collectors. Every method is safe to
// call on a nil *Metrics, so a Server without metrics needs no checks.
type Metrics struct {
	sessions prometheus.Gauge
	logins   *prometheus.CounterVec
	revokes  prometheus.Counter
	stale    prometheus.Counter
	preAuth  prometheus.Counter
	bytes    *prometheus.CounterVec
}

// NewMetrics builds the collectors and registers them with reg. Use a
// private registry, not the process default.
func NewMetrics(reg prometheus.Registerer) (*Metrics, error) {
	m := &Metrics{
		sessions: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "gameplane_sftp_sessions",
			Help: "Authenticated SSH connections currently open.",
		}),
		logins: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "gameplane_sftp_logins_total",
			Help: "Login attempts by result.",
		}, []string{"result"}),
		revokes: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "gameplane_sftp_revoked_total",
			Help: "Connections closed because their session was revoked.",
		}),
		stale: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "gameplane_sftp_unconfirmed_closed_total",
			Help: "Connections closed because the API had not confirmed their session in time (failed checks or expiry).",
		}),
		preAuth: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "gameplane_sftp_preauth_rejected_total",
			Help: "Connections closed at once because too many were still authenticating.",
		}),
		bytes: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "gameplane_sftp_bytes_total",
			Help: "File bytes transferred, by direction (read or write).",
		}, []string{"direction"}),
	}
	for _, c := range []prometheus.Collector{m.sessions, m.logins, m.revokes, m.stale, m.preAuth, m.bytes} {
		if err := reg.Register(c); err != nil {
			return nil, fmt.Errorf("register sftp metrics: %w", err)
		}
	}
	// Create every result series up front so each one shows as 0 from the
	// first scrape.
	for _, r := range []string{loginOK, loginDenied, loginError, loginLimit} {
		m.logins.WithLabelValues(r)
	}
	for _, d := range []string{"read", "write"} {
		m.bytes.WithLabelValues(d)
	}
	return m, nil
}

// AddBytes counts n transferred bytes in direction "read" or "write". It
// matches the OnBytes hook of the virtual file system.
func (m *Metrics) AddBytes(direction string, n int) {
	if m == nil || n <= 0 {
		return
	}
	m.bytes.WithLabelValues(direction).Add(float64(n))
}

func (m *Metrics) login(result string) {
	if m == nil {
		return
	}
	m.logins.WithLabelValues(result).Inc()
}

func (m *Metrics) sessionOpened() {
	if m == nil {
		return
	}
	m.sessions.Inc()
}

func (m *Metrics) sessionClosed() {
	if m == nil {
		return
	}
	m.sessions.Dec()
}

func (m *Metrics) revoked() {
	if m == nil {
		return
	}
	m.revokes.Inc()
}

func (m *Metrics) preAuthRejected() {
	if m == nil {
		return
	}
	m.preAuth.Inc()
}

func (m *Metrics) unconfirmed() {
	if m == nil {
		return
	}
	m.stale.Inc()
}
