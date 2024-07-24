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

// Package cirrus is the primary package container for the Cirrus ReST service.
package cirrus

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"net/http"
	"os"
	"sync/atomic"
	"time"

	"github.com/PurpleSec/logx"
	"github.com/PurpleSec/routex"
	"github.com/gorilla/websocket"
	"github.com/iDigitalFlame/xmt/c2"
	"github.com/iDigitalFlame/xmt/c2/cfg"
	"github.com/iDigitalFlame/xmt/com"
	"github.com/iDigitalFlame/xmt/device"
	"github.com/iDigitalFlame/xmt/util"
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
	log       logx.Log
	ctx       context.Context
	cancel    context.CancelFunc
	jobs      *jobManager
	st        *stats
	ch        chan struct{}
	mux       *routex.Mux
	ws        *websocket.Upgrader
	listeners *listenerManager
	s         *c2.Server
	events    *eventManager
	packets   *packetManager
	scripts   *scriptManager
	profiles  *profileManager
	sessions  *sessionManager

	Auth string
	srv  http.Server

	Timeout time.Duration
}

// Close stops all Cirrus instances and listening endpoints.
//
// This will NOT close any Sessions or Listeners created.
func (c *Cirrus) Close() error {
	if c.cancel(); c.st != nil {
		<-c.st.ch
	}
	if atomic.LoadUint32(&c.events.status) == 0 {
		c.events.shutdown()
	}
	<-c.ch
	var (
		x, f = context.WithTimeout(context.Background(), time.Second*5)
		err  = c.srv.Shutdown(x)
	)
	f()
	c.srv.Close()
	return err
}

// Save will attempt to save the current state of Cirrus (Listeners, Scripts and
// Profiles) to the supplied file path as pretty JSON. If successful, the file
// will be truncated (if it exists) and overwritten.
//
// Any environment variables will be parsed and expanded before writing.
//
// This function will bail and return any encoding or writing errors that may
// occur during the operation.
func (c *Cirrus) Save(s string) error {

	b, err := json.MarshalIndent(map[string]any{
		"auth": c.Auth,
		"keys": map[string]string{
			"public":  c.s.Keys.Public.String(),
			"private": c.s.Keys.Private.String(),
		},
		"timeout":   c.Timeout,
		"scripts":   c.scripts,
		"profiles":  c.profiles,
		"mappings":  c.sessions.hw,
		"listeners": c.listeners,
	}, "", "    ")
	if err != nil {
		return err
	}
	return os.WriteFile(device.Expand(s), b, 0o640)
}

// Load will attempt to load in a previously saved Cirrus state from the provided
// JSON file. If the path does not exist, this function will return without an
// error (allows loading from an empty state file).
//
// Any environment variables will be parsed and expanded before loading.
//
// This function will bail and return any encoding or reading errors that may
// occur during the operation.
func (c *Cirrus) Load(s string) error {
	p := device.Expand(s)
	if _, err := os.Stat(p); err != nil {
		return nil
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return err
	}
	var m map[string]json.RawMessage
	if err = json.Unmarshal(b, &m); err != nil {
		return err
	}
	// Load keys first.
	if t, ok := m["keys"]; ok {
		var v map[string]string
		if err = json.Unmarshal(t, &v); err != nil {
			return err
		}
		var (
			h, ok1 = v["public"]
			j, ok2 = v["private"]
		)
		if ok1 && ok2 && len(h) > 0 && len(j) > 0 {
			if err = c.s.Keys.Public.Parse(h); err != nil {
				return err
			}
			if err = c.s.Keys.Private.Parse(j); err != nil {
				return err
			}
		}
	}
	if t, ok := m["auth"]; ok {
		if err = json.Unmarshal(t, &c.Auth); err != nil {
			return err
		}
	}
	if t, ok := m["timeout"]; ok {
		if err = json.Unmarshal(t, &c.Timeout); err != nil {
			return err
		}
	}
	if t, ok := m["profiles"]; ok {
		if err = json.Unmarshal(t, &c.profiles); err != nil {
			return err
		}
	}
	if t, ok := m["scripts"]; ok {
		if err = json.Unmarshal(t, &c.scripts); err != nil {
			return err
		}
	}
	if t, ok := m["mappings"]; ok {
		if err = json.Unmarshal(t, &c.sessions.hw); err != nil {
			return err
		}
	}
	// Load listeners since they rely on all the above to work.
	if t, ok := m["listeners"]; ok {
		if err = json.Unmarshal(t, &c.listeners); err != nil {
			return err
		}
	}
	return nil
}

// Listen will bind to the specified address and begin serving requests.
// This function will return when the server is closed.
func (c *Cirrus) Listen(addr string) error {
	return c.ListenTLS(addr, "", "")
}
func configureRoutes(c *Cirrus, m *routex.Mux) {
	m.Must(prefix+`/server$`, routex.Func(c.httpServerInfoGet), http.MethodGet)
	m.Must(prefix+`/script$`, routex.Func(c.scripts.httpScriptsGet), http.MethodGet)
	m.Must(prefix+`/script/(?P<name>[a-zA-Z0-9\-._]+)$`, routex.Func(c.scripts.httpScriptGet), http.MethodGet)
	m.Must(prefix+`/script/(?P<name>[a-zA-Z0-9\-._]+)$`, routex.Func(c.scripts.httpScriptDelete), http.MethodDelete)
	m.Must(prefix+`/script/(?P<name>[a-zA-Z0-9\-._]+)$`, routex.Wrap(valScriptRollback, routex.WrapFunc(c.scripts.httpScriptRollback)), http.MethodPatch)
	m.Must(prefix+`/script/(?P<name>[a-zA-Z0-9\-._]+)$`, routex.Marshal[scriptArgs](valScript, routex.MarshalFunc[scriptArgs](c.scripts.httpScriptPutPost)), http.MethodPut, http.MethodPost)
	m.Must(prefix+`/script/(?P<name>[a-zA-Z0-9\-._]+)/note$`, routex.Wrap(ws(nil), routex.WrapFunc(c.scripts.httpScriptNote)), http.MethodPut)
	m.Must(prefix+`/script/(?P<name>[a-zA-Z0-9\-._]+)/exec$`, routex.Marshal[taskCommand](ws(valTaskSimple), routex.MarshalFunc[taskCommand](c.scripts.httpScriptCommand)), http.MethodPut)
	m.Must(prefix+`/script/(?P<name>[a-zA-Z0-9\-._]+)/proxy$`, routex.Wrap(valScriptProxyDelete, routex.WrapFunc(c.scripts.httpScriptProxyDelete)), http.MethodDelete)
	m.Must(prefix+`/script/(?P<name>[a-zA-Z0-9\-._]+)/proxy$`, routex.Wrap(valScriptProxyAddUpdate, routex.WrapFunc(c.scripts.httpScriptProxyPutPost)), http.MethodPut, http.MethodPost)
	m.Must(prefix+`/script/(?P<name>[a-zA-Z0-9\-._]+)/pull$`, routex.Wrap(ws(valTaskPull), routex.WrapFunc(c.scripts.httpScriptPull)), http.MethodPut)
	m.Must(prefix+`/script/(?P<name>[a-zA-Z0-9\-._]+)/login$`, routex.Wrap(ws(valTaskLogin), routex.WrapFunc(c.scripts.httpScriptLogin)), http.MethodPut)
	m.Must(prefix+`/script/(?P<name>[a-zA-Z0-9\-._]+)/io$`, routex.Wrap(ws(valTaskSystemIo), routex.WrapFunc(c.scripts.httpScriptSystemIo)), http.MethodPut)
	m.Must(prefix+`/script/(?P<name>[a-zA-Z0-9\-._]+)/ui$`, routex.Wrap(ws(valTaskWindowUI), routex.WrapFunc(c.scripts.httpScriptWindowUI)), http.MethodPut)
	m.Must(prefix+`/script/(?P<name>[a-zA-Z0-9\-._]+)/upload$`, routex.Wrap(ws(valTaskUpload), routex.WrapFunc(c.scripts.httpScriptUpload)), http.MethodPut)
	m.Must(prefix+`/script/(?P<name>[a-zA-Z0-9\-._]+)/profile$`, routex.Wrap(ws(valTaskProfile), routex.WrapFunc(c.scripts.httpScriptProfile)), http.MethodPut)
	m.Must(prefix+`/script/(?P<name>[a-zA-Z0-9\-._]+)/regedit$`, routex.Wrap(ws(valTaskRegistry), routex.WrapFunc(c.scripts.httpScriptRegistry)), http.MethodPut)
	m.Must(prefix+`/script/(?P<name>[a-zA-Z0-9\-._]+)/download$`, routex.Wrap(ws(valTaskDownload), routex.WrapFunc(c.scripts.httpScriptDownload)), http.MethodPut)
	m.Must(prefix+`/script/(?P<name>[a-zA-Z0-9\-._]+)/dll$`, routex.Marshal[taskDLL](ws(valTaskDLL), routex.MarshalFunc[taskDLL](c.scripts.httpScriptDLL)), http.MethodPut)
	m.Must(prefix+`/script/(?P<name>[a-zA-Z0-9\-._]+)/dll/check$`, routex.Marshal[taskCheck](ws(valTaskPatchCheck), routex.MarshalFunc[taskCheck](c.scripts.httpScriptCheck)), http.MethodPut)
	m.Must(prefix+`/script/(?P<name>[a-zA-Z0-9\-._]+)/dll/patch$`, routex.Marshal[taskPatch](ws(valTaskPatchCheck), routex.MarshalFunc[taskPatch](c.scripts.httpScriptPatch)), http.MethodPut)
	m.Must(prefix+`/script/(?P<name>[a-zA-Z0-9\-._]+)/pexec$`, routex.Marshal[taskPull](ws(valPullEx), routex.MarshalFunc[taskPull](c.scripts.httpScriptPexec)), http.MethodPut)
	m.Must(prefix+`/script/(?P<name>[a-zA-Z0-9\-._]+)/spawn$`, routex.Marshal[taskSpawn](ws(valTaskSpawn), routex.MarshalFunc[taskSpawn](c.scripts.httpScriptSpawn)), http.MethodPut)
	m.Must(prefix+`/script/(?P<name>[a-zA-Z0-9\-._]+)/sys$`, routex.Marshal[taskSystem](ws(valTaskSystem), routex.MarshalFunc[taskSystem](c.scripts.httpScriptSystem)), http.MethodPut)
	m.Must(prefix+`/script/(?P<name>[a-zA-Z0-9\-._]+)/sys/workhours$`, routex.Marshal[taskWorkHours](ws(valTaskWorkHours), routex.MarshalFunc[taskWorkHours](c.scripts.httpScriptWorkHours)), http.MethodPut)
	m.Must(prefix+`/script/(?P<name>[a-zA-Z0-9\-._]+)/zombie$`, routex.Marshal[taskZombie](ws(valTaskZombie), routex.MarshalFunc[taskZombie](c.scripts.httpScriptZombie)), http.MethodPut)
	m.Must(prefix+`/script/(?P<name>[a-zA-Z0-9\-._]+)/exec$`, routex.Marshal[taskCommand](ws(valTaskSimple), routex.MarshalFunc[taskCommand](c.scripts.httpScriptCommand)), http.MethodPut)
	m.Must(prefix+`/script/(?P<name>[a-zA-Z0-9\-._]+)/migrate$`, routex.Marshal[taskMigrate](ws(valTaskMigrate), routex.MarshalFunc[taskMigrate](c.scripts.httpScriptMigrate)), http.MethodPut)
	m.Must(prefix+`/script/(?P<name>[a-zA-Z0-9\-._]+)/asm$`, routex.Marshal[taskAssembly](ws(valTaskAssembly), routex.MarshalFunc[taskAssembly](c.scripts.httpScriptAssembly)), http.MethodPut)
	m.Must(prefix+`/script/(?P<name>[a-zA-Z0-9\-._]+)/wts$`, routex.Wrap(ws(valTaskWTS), routex.WrapFunc(c.scripts.httpScriptWTS)), http.MethodPut)
	m.Must(prefix+`/script/(?P<name>[a-zA-Z0-9\-._]+)/evade$`, routex.Wrap(ws(valTaskEvade), routex.WrapFunc(c.scripts.httpScriptEvade)), http.MethodPut)
	m.Must(prefix+`/script/(?P<name>[a-zA-Z0-9\-._]+)/power$`, routex.Marshal[taskPower](ws(valTaskPower), routex.MarshalFunc[taskPower](c.scripts.httpScriptPower)), http.MethodPut)
	m.Must(prefix+`/script/(?P<name>[a-zA-Z0-9\-._]+)/net$`, routex.Marshal[taskNetcat](ws(valTaskNetcat), routex.MarshalFunc[taskNetcat](c.scripts.httpScriptNetcat)), http.MethodPut)
	m.Must(prefix+`/script/(?P<name>[a-zA-Z0-9\-._]+)/funcmap$`, routex.Marshal[taskFuncmap](ws(valTaskFuncmap), routex.MarshalFunc[taskFuncmap](c.scripts.httpScriptFuncmap)), http.MethodPut)
	m.Must(prefix+`/events$`, routex.Func(c.websocket), http.MethodGet)
	m.Must(prefix+`/packet$`, routex.Func(c.packets.httpPacketsGet), http.MethodGet)
	m.Must(prefix+`/packet/(?P<name>[a-z]+)$`, routex.Func(c.packets.httpPacketGetDelete), http.MethodGet, http.MethodDelete)
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
	m.Must(prefix+`/listener/(?P<name>[a-zA-Z0-9\-._]+)/script$`, routex.Wrap(valListenerScript, routex.WrapFunc(c.listeners.httpListenerScriptPost)), http.MethodPost)
	m.Must(prefix+`/session$`, routex.Func(c.sessions.httpSessionsGet), http.MethodGet)
	m.Must(prefix+`/session/(?P<session>[a-zA-Z0-9\-._]+)$`, routex.Func(c.sessions.httpSessionGet), http.MethodGet)
	m.Must(prefix+`/session/(?P<session>[a-zA-Z0-9\-._]+)$`, routex.Func(c.sessions.httpSessionDelete), http.MethodDelete)
	m.Must(prefix+`/session/(?P<session>[a-zA-Z0-9\-._]+)/proxy/(?P<name>[a-zA-Z0-9\-._]+)$`, routex.Func(c.sessions.httpSessionProxyDelete), http.MethodDelete)
	m.Must(prefix+`/session/(?P<session>[a-zA-Z0-9\-._]+)/proxy/(?P<name>[a-zA-Z0-9\-._]+)$`, routex.Wrap(valListener, routex.WrapFunc(c.sessions.httpSessionProxyPutPost)), http.MethodPut, http.MethodPost)
	m.Must(prefix+`/session/(?P<session>[a-zA-Z0-9\-._]+)/job$`, routex.Func(c.jobs.httpJobsGet), http.MethodGet)
	m.Must(prefix+`/session/(?P<session>[a-zA-Z0-9\-._]+)/job/(?P<job>[0-9]+)$`, routex.Func(c.jobs.httpJobGetDelete), http.MethodGet, http.MethodDelete)
	m.Must(prefix+`/session/(?P<session>[a-zA-Z0-9\-._]+)/job/(?P<job>[0-9]+)/result$`, routex.Func(c.jobs.httpJobResultGetDelete), http.MethodGet, http.MethodDelete)
	m.Must(prefix+`/session/(?P<session>[a-zA-Z0-9\-._]+)/pull$`, routex.Wrap(valTaskPull, routex.WrapFunc(c.sessions.httpTaskPull)), http.MethodPut)
	m.Must(prefix+`/session/(?P<session>[a-zA-Z0-9\-._]+)/name$`, routex.Func(c.sessions.httpSessionRename), http.MethodPut)
	m.Must(prefix+`/session/(?P<session>[a-zA-Z0-9\-._]+)/login$`, routex.Wrap(valTaskLogin, routex.WrapFunc(c.sessions.httpTaskLogin)), http.MethodPut)
	m.Must(prefix+`/session/(?P<session>[a-zA-Z0-9\-._]+)/io$`, routex.Wrap(valTaskSystemIo, routex.WrapFunc(c.sessions.httpTaskSystemIo)), http.MethodPut)
	m.Must(prefix+`/session/(?P<session>[a-zA-Z0-9\-._]+)/ui$`, routex.Wrap(valTaskWindowUI, routex.WrapFunc(c.sessions.httpTaskWindowUI)), http.MethodPut)
	m.Must(prefix+`/session/(?P<session>[a-zA-Z0-9\-._]+)/script$`, routex.Wrap(valTaskScript, routex.WrapFunc(c.sessions.httpTaskScript)), http.MethodPut)
	m.Must(prefix+`/session/(?P<session>[a-zA-Z0-9\-._]+)/upload$`, routex.Wrap(valTaskUpload, routex.WrapFunc(c.sessions.httpTaskUpload)), http.MethodPut)
	m.Must(prefix+`/session/(?P<session>[a-zA-Z0-9\-._]+)/profile$`, routex.Wrap(valTaskProfile, routex.WrapFunc(c.sessions.httpTaskProfile)), http.MethodPut)
	m.Must(prefix+`/session/(?P<session>[a-zA-Z0-9\-._]+)/regedit$`, routex.Wrap(valTaskRegistry, routex.WrapFunc(c.sessions.httpTaskRegistry)), http.MethodPut)
	m.Must(prefix+`/session/(?P<session>[a-zA-Z0-9\-._]+)/download$`, routex.Wrap(valTaskDownload, routex.WrapFunc(c.sessions.httpTaskDownload)), http.MethodPut)
	m.Must(prefix+`/session/(?P<session>[a-zA-Z0-9\-._]+)/dll$`, routex.Marshal[taskDLL](valTaskDLL, routex.MarshalFunc[taskDLL](c.sessions.httpTaskDLL)), http.MethodPut)
	m.Must(prefix+`/session/(?P<session>[a-zA-Z0-9\-._]+)/dll/check$`, routex.Marshal[taskCheck](valTaskPatchCheck, routex.MarshalFunc[taskCheck](c.sessions.httpTaskCheck)), http.MethodPut)
	m.Must(prefix+`/session/(?P<session>[a-zA-Z0-9\-._]+)/dll/patch$`, routex.Marshal[taskPatch](valTaskPatchCheck, routex.MarshalFunc[taskPatch](c.sessions.httpTaskPatch)), http.MethodPut)
	m.Must(prefix+`/session/(?P<session>[a-zA-Z0-9\-._]+)/pexec$`, routex.Marshal[taskPull](valPullEx, routex.MarshalFunc[taskPull](c.sessions.httpTaskPexec)), http.MethodPut)
	m.Must(prefix+`/session/(?P<session>[a-zA-Z0-9\-._]+)/spawn$`, routex.Marshal[taskSpawn](valTaskSpawn, routex.MarshalFunc[taskSpawn](c.sessions.httpTaskSpawn)), http.MethodPut)
	m.Must(prefix+`/session/(?P<session>[a-zA-Z0-9\-._]+)/sys$`, routex.Marshal[taskSystem](valTaskSystem, routex.MarshalFunc[taskSystem](c.sessions.httpTaskSystem)), http.MethodPut)
	m.Must(prefix+`/session/(?P<session>[a-zA-Z0-9\-._]+)/sys/workhours$`, routex.Marshal[taskWorkHours](valTaskWorkHours, routex.MarshalFunc[taskWorkHours](c.sessions.httpTaskWorkHours)), http.MethodPut)
	m.Must(prefix+`/session/(?P<session>[a-zA-Z0-9\-._]+)/zombie$`, routex.Marshal[taskZombie](valTaskZombie, routex.MarshalFunc[taskZombie](c.sessions.httpTaskZombie)), http.MethodPut)
	m.Must(prefix+`/session/(?P<session>[a-zA-Z0-9\-._]+)/exec$`, routex.Marshal[taskCommand](valTaskSimple, routex.MarshalFunc[taskCommand](c.sessions.httpTaskCommand)), http.MethodPut)
	m.Must(prefix+`/session/(?P<session>[a-zA-Z0-9\-._]+)/migrate$`, routex.Marshal[taskMigrate](valTaskMigrate, routex.MarshalFunc[taskMigrate](c.sessions.httpTaskMigrate)), http.MethodPut)
	m.Must(prefix+`/session/(?P<session>[a-zA-Z0-9\-._]+)/asm$`, routex.Marshal[taskAssembly](valTaskAssembly, routex.MarshalFunc[taskAssembly](c.sessions.httpTaskAssembly)), http.MethodPut)
	m.Must(prefix+`/session/(?P<session>[a-zA-Z0-9\-._]+)/wts$`, routex.Wrap(valTaskWTS, routex.WrapFunc(c.sessions.httpTaskWTS)), http.MethodPut)
	m.Must(prefix+`/session/(?P<session>[a-zA-Z0-9\-._]+)/evade$`, routex.Wrap(valTaskEvade, routex.WrapFunc(c.sessions.httpTaskEvade)), http.MethodPut)
	m.Must(prefix+`/session/(?P<session>[a-zA-Z0-9\-._]+)/power$`, routex.Marshal[taskPower](valTaskPower, routex.MarshalFunc[taskPower](c.sessions.httpTaskPower)), http.MethodPut)
	m.Must(prefix+`/session/(?P<session>[a-zA-Z0-9\-._]+)/net$`, routex.Marshal[taskNetcat](valTaskNetcat, routex.MarshalFunc[taskNetcat](c.sessions.httpTaskNetcat)), http.MethodPut)
	m.Must(prefix+`/session/(?P<session>[a-zA-Z0-9\-._]+)/funcmap$`, routex.Marshal[taskFuncmap](valTaskFuncmap, routex.MarshalFunc[taskFuncmap](c.sessions.httpTaskFuncmap)), http.MethodPut)
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
	c.st = &stats{
		ch: make(chan struct{}),
		ej: make(chan statJobEvent, 64),
		ep: make(chan statPacketEvent, 64),
		es: make(chan statSessionEvent, 64),
	}
	if len(csv) > 0 {
		var (
			v, err = os.Stat(csv)
			h      = err != nil || v.Size() == 0
		)
		// 0x1441 - os.O_APPEND|os.O_CREATE|os.O_WRONLY|os.O_SYNC
		if c.st.f, err = os.OpenFile(csv, 0x1441, 0o640); err != nil {
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
	// 0x1441 - os.O_APPEND|os.O_CREATE|os.O_WRONLY|os.O_SYNC
	if c.st.t, err = os.OpenFile(tracker, 0x1441, 0o640); err != nil {
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
		c.log.Info("[cirrus] Starting Tracking thread!")
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
		CurvePreferences: []tls.CurveID{tls.CurveP521, tls.CurveP256, tls.X25519},
	}
	if err := c.srv.ListenAndServeTLS(cert, key); err != http.ErrServerClosed {
		c.Close()
		return err
	}
	return nil
}

// New creates a new Cirrus REST server instance using the supplied C2 Server.
//
// The provided key can be used to authenticate to the Rest service with the
// 'X-CirrusAuth' HTTP header containing the supplied key.
//
// If empty, authentication is disabled.
func New(s *c2.Server, log logx.Log, key string) *Cirrus {
	return NewContext(context.Background(), s, log, key)
}

// Listen is a quick utility function that allows for creation of a new
// Cirrus REST service and will start it immediately.
//
// This function will block until the server is closed.
//
// Quick version of "NewContext(context.Background(), s, log, key).Listen(addr)".
func Listen(s *c2.Server, log logx.Log, key, addr string) error {
	return NewContext(context.Background(), s, log, key).Listen(addr)
}

// NewContext creates a new Cirrus REST server instance using the supplied C2
// Server instance.
//
// This function allows specifying a Context to aid in cancellation.
func NewContext(x context.Context, s *c2.Server, log logx.Log, key string) *Cirrus {
	c := &Cirrus{s: s, Auth: key, Timeout: timeout, ch: make(chan struct{}), log: log}
	c.jobs = &jobManager{Cirrus: c, e: make(map[uint64]*c2.Job)}
	c.packets = &packetManager{Cirrus: c, e: make(map[string]*packet)}
	c.scripts = &scriptManager{Cirrus: c, e: make(map[string]*script)}
	c.profiles = &profileManager{Cirrus: c, e: make(map[string]cfg.Config)}
	c.listeners = &listenerManager{Cirrus: c, e: make(map[string]*listener)}
	c.events = &eventManager{Cirrus: c, in: make(chan event, 256), new: make(chan *websocket.Conn, 64)}
	c.sessions = &sessionManager{Cirrus: c, e: make(map[string]*session), names: make(map[string]*session), hw: make(map[string]string)}
	c.ctx, c.cancel = context.WithCancel(x)
	c.srv.BaseContext, c.mux = c.context, routex.NewContext(x)
	c.mux.Middleware(encoding)
	c.mux.Middleware(c.auth)
	c.mux.Error = routex.ErrorFunc(writeError)
	c.ws = &websocket.Upgrader{
		CheckOrigin:      func(_ *http.Request) bool { return true },
		ReadBufferSize:   1024,
		WriteBufferSize:  1024,
		HandshakeTimeout: time.Second * 5,
	}
	if configureRoutes(c, c.mux); c.log == nil {
		c.log = logx.NOP
	} else {
		c.log.SetPrintLevel(logx.Trace)
		c.mux.SetLog(c.log)
	}
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
			c.packetNew(n)
		}
	} else {
		s.Oneshot = c.packetNew
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
// Quick version of "NewContext(x, s, log, key).Listen(addr)".
//
// This function allows specifying a Context to aid in cancellation.
func ListenContext(x context.Context, s *c2.Server, log logx.Log, key, addr string) error {
	return NewContext(x, s, log, key).Listen(addr)
}
func (c *Cirrus) httpServerInfoGet(_ context.Context, w http.ResponseWriter, _ *routex.Request) {
	if c.s.Keys.Public.Empty() {
		w.Write([]byte(`{}`))
		return
	}
	w.Write([]byte(`{"public_key":"` + c.s.Keys.Public.String() + `","public_key_hash":"` + util.Uitoa16(uint64(c.s.Keys.Public.Hash())) + `"}`))
}
