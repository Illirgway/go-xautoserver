package xautoserver

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"sync/atomic"
	"time"
	"unsafe"
)

const (
	watchCertsTimeThreshold = 60	// secs
)

// https://wiki.mozilla.org/Security/Server_Side_TLS#Modern_compatibility

var (
	tlsNextProtos = []string{
		"http/1.1",
	}

	// not included due to absence in golang
	// 0xC0,0x24  -  ECDHE-ECDSA-AES256-SHA384      TLSv1.2  Kx=ECDH  Au=ECDSA  Enc=AES(256)       Mac=SHA384
	// 0xC0,0x28  -  ECDHE-RSA-AES256-SHA384        TLSv1.2  Kx=ECDH  Au=RSA    Enc=AES(256)       Mac=SHA384
	strongCiperSuites = []uint16{
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
		tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
	}

	// secp256r1 (NIST P-256) is unsafe due to its NSA DRNG)
	// https://safecurves.cr.yp.to/rigid.html
	modernCurvePreferences = []tls.CurveID{
		tls.X25519, tls.CurveP521, tls.CurveP384, tls.CurveP256,
	}

	sessionCacheCapacity = 256	// cache records (stored tickets)
)


type manager struct {
	c		*TLSConfig
	// cache
	ci		unsafe.Pointer	// *certInfo
	logger	*log.Logger

	stop	context.CancelFunc
}

// instead of logger, use callback for error handling
func newManager(c *TLSConfig, logger *log.Logger) (*manager, error) {

	if c == nil {
		return nil, fmt.Errorf("%s manager error: tls config cannot be nil", pkgErrPrefix)
	}

	// -1 is unreal minimal absolute linux UTS
	ci, err := helperWatchCertsChanges(c, -1)
	if err != nil {
		return nil, fmt.Errorf("%s manager error: initial cert load error: %s", pkgErrPrefix, err.Error())
	}

	m := &manager{
		c: c.clone(),
		logger: logger,
	}

	if err := m.init(ci); err != nil {
		return nil, err
	}

	return m, nil
}

// IHBD HIGH cipher suites
// TODO configurable ClientAuth
// TODO configurable ClientSessionCache capacity
// TODO configurable CurvePreferences, CipherSuites
func (m *manager) TLSStrongConfig() *tls.Config {
	return &tls.Config{
		GetCertificate: m.GetCertificate,
		NextProtos: tlsNextProtos,
		ClientAuth: tls.VerifyClientCertIfGiven,
		PreferServerCipherSuites: true,
		ClientSessionCache: tls.NewLRUClientSessionCache(sessionCacheCapacity),
		MinVersion: tls.VersionTLS12,
		// don't set MaxVersion for auto set by tls pkg depends on golang version
		CurvePreferences: modernCurvePreferences,
		CipherSuites: strongCiperSuites,
	}
}

func (m *manager) certs() (*tls.Certificate, error) {

	// no need for lock, use atomic pointers
	ci := m.atomGetCI()

	return ci.tlscert(), nil
}

func (m *manager) updateCI() bool {

	ci, err := helperWatchCertsChanges(
		m.c, m.atomGetCI().mtime())

	if err != nil {
		// log and use old cached certs
		m.logger.Printf("CRITICAL cert renew ERROR: %s!", err)
		return false
	}

	if ci != nil {	// renew only if ci is not nil
		// for return below
		m.atomSetCI(ci)

		m.logger.Printf("success cert renewal with mtime %d", ci.mtime())
	}

	return true
}

// TODO configurable watchCertsTimeThreshold
func (m *manager) watcher(ctx context.Context) {
	delta := watchCertsTimeThreshold * time.Second
	// once-fired timer with manual reset guaranteed that we execute no more than one updateCI in time
	ticker := time.NewTimer(delta)
L:
	for {
		select {

		case <-ctx.Done():
			if !ticker.Stop() {
				<-ticker.C
			}
			break L

		case <-ticker.C:
			// TODO use true / false retval to select d for Reset(d)
			m.updateCI()
			ticker.Reset(delta)
		}
	}
}

func (m *manager) init(ci *certInfo) error {

	// first must set ci
	m.atomSetCI(ci)

	{
		ctx, stop := context.WithCancel(context.Background())

		m.stop = stop

		// start certs watcher
		go m.watcher(ctx)
	}

	return nil
}

func (m *manager) Stop() {
	m.stop()
}

func (m *manager) GetCertificate(chi *tls.ClientHelloInfo) (*tls.Certificate, error) {
	return m.certs()
}

func (m *manager) atomGetCI() *certInfo {
	return (*certInfo)(atomic.LoadPointer(&m.ci))
}

// chained ci
func (m *manager) atomSetCI(ci *certInfo) *certInfo {
	atomic.StorePointer(&m.ci, unsafe.Pointer(ci))
	return ci
}

func (m *manager) Mtime() int64 {
	return m.atomGetCI().mtime()
}