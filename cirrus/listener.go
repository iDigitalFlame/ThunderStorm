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
	"encoding/json"
	"net/http"
	"strings"
	"sync"

	"github.com/PurpleSec/escape"
	"github.com/PurpleSec/routex"
	"github.com/PurpleSec/routex/val"
	"github.com/iDigitalFlame/xmt/c2"
	"github.com/iDigitalFlame/xmt/c2/cfg"
	"github.com/iDigitalFlame/xmt/util/xerr"
)

const msgNoListener = "listener was not found"

var (
	valListener = val.Set{
		val.Validator{Name: "script", Type: val.String, Optional: true},
		val.Validator{Name: "address", Type: val.String, Rules: val.Rules{val.Length{Min: 1, Max: 256}}},
		val.Validator{Name: "profile", Type: val.String, Optional: true, Rules: val.Rules{val.Length{Min: 1, Max: 256}}},
	}
	valListenerScript = val.Set{
		val.Validator{Name: "script", Type: val.String, Rules: val.Rules{val.Length{Min: 0, Max: 256}}},
	}
)

type listener struct {
	l       *c2.Listener
	n, a, s string
	p       cfg.Config
}
type listenerManager struct {
	*Cirrus
	sync.RWMutex

	e map[string]*listener
}

func (l *listener) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]any{
		"script":       l.s,         // Optional
		"address":      l.a,         // Required
		"profile":      []byte(l.p), // Required
		"profile_name": l.n,         // Optional
	})
}
func (l *listener) UnmarshalJSON(b []byte) error {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(b, &m); err != nil {
		return err
	}
	t, ok := m["address"]
	if !ok {
		return xerr.New(`json: listener is missing "address"`)
	}
	if err := json.Unmarshal(t, &l.a); err != nil {
		return err
	}
	if t, ok = m["profile"]; !ok {
		return xerr.New(`json: listener is missing "profile"`)
	}
	var k []byte
	if err := json.Unmarshal(t, &k); err != nil {
		return err
	}
	l.p, k = k, nil
	if t, ok = m["script"]; ok {
		if err := json.Unmarshal(t, &l.s); err != nil {
			return err
		}
	}
	if t, ok = m["profile_name"]; ok {
		if err := json.Unmarshal(t, &l.n); err != nil {
			return err
		}
	}
	return nil
}
func (l *listenerManager) MarshalJSON() ([]byte, error) {
	l.Lock()
	b, err := json.Marshal(l.e)
	l.Unlock()
	return b, err
}
func (l *listenerManager) UnmarshalJSON(b []byte) error {
	var (
		m   map[string]*listener
		err = json.Unmarshal(b, &m)
	)
	if err != nil {
		return err
	}
	l.Lock()
	for k, v := range m {
		if _, ok := l.e[k]; ok {
			continue
		}
		var c cfg.Config
		if len(v.p) > 0 {
			c = v.p
		} else if len(v.n) > 0 {
			c, _ = l.profile(v.n)
		}
		if len(c) == 0 {
			err = xerr.New(`json: listener "` + k + `" does not have a valid profile`)
			break
		}
		var p c2.Profile
		if p, err = c.Build(); err != nil {
			err = xerr.Wrap(`json: listener "`+k+`" profile build`, err)
			break
		}
		if v.l, err = l.s.Listen(k, v.a, p); err != nil {
			err = xerr.Wrap(`json: listener "`+k+`" listen failed`, err)
			break
		}
		l.e[k] = v
	}
	l.Unlock()
	return err
}
func writeListener(c int, w http.ResponseWriter, l *listener) {
	if c > 0 {
		w.WriteHeader(c)
	}
	w.Write([]byte(`{"profile_name":` + escape.JSON(l.n) + `,"profile":"`))
	writeBase64(w, l.p.Bytes())
	w.Write([]byte(`","script":` + escape.JSON(l.s) + `,"bind":` + escape.JSON(l.a) + `,"listener":`))
	l.l.JSON(w)
	w.Write([]byte{'}'})
}
func (l *listenerManager) httpListenerGet(_ context.Context, w http.ResponseWriter, r *routex.Request) {
	n := r.Values.StringDefault("name", "")
	if len(n) == 0 || !isValidName(n) {
		writeError(http.StatusNotFound, msgNoListener, w, r)
		return
	}
	i := strings.ToLower(n)
	l.RLock()
	v, ok := l.e[i]
	if l.RUnlock(); !ok {
		writeError(http.StatusNotFound, msgNoListener, w, r)
		return
	}
	writeListener(http.StatusOK, w, v)
}
func (l *listenerManager) httpListenersGet(_ context.Context, w http.ResponseWriter, _ *routex.Request) {
	w.Write([]byte{'{'})
	if l.RLock(); len(l.e) > 0 {
		var n int
		for k, v := range l.e {
			if n > 0 {
				w.Write([]byte{','})
			}
			w.Write([]byte(escape.JSON(k) + `:`))
			writeListener(0, w, v)
			n++
		}
	}
	l.RUnlock()
	w.Write([]byte{'}'})
}
func (l *listenerManager) httpListenerDelete(_ context.Context, w http.ResponseWriter, r *routex.Request) {
	n := r.Values.StringDefault("name", "")
	if len(n) == 0 || !isValidName(n) {
		writeError(http.StatusNotFound, msgNoListener, w, r)
		return
	}
	i := strings.ToLower(n)
	l.RLock()
	v, ok := l.e[i]
	if l.RUnlock(); !ok {
		writeError(http.StatusNotFound, msgNoListener, w, r)
		return
	}
	if err := v.l.Close(); err != nil {
		writeError(http.StatusInternalServerError, "listener close failed: "+err.Error(), w, r)
		return
	}
	v.l, v.p = nil, nil
	l.Lock()
	l.e[i] = nil
	delete(l.e, i)
	l.Unlock()
	l.events.publishListenerDelete(i)
	w.WriteHeader(http.StatusOK)
}
func (l *listenerManager) httpListenerPut(_ context.Context, w http.ResponseWriter, r *routex.Request, c routex.Content) {
	n := r.Values.StringDefault("name", "")
	if len(n) == 0 || !isValidName(n) {
		writeError(http.StatusBadRequest, `value "name" cannot be empty or invalid`, w, r)
		return
	}
	var (
		b    = c.StringDefault("address", "")
		q, z = l.script(c.StringDefault("script", ""))
		p, v = l.profile(c.StringDefault("profile", ""))
	)
	if len(b) == 0 {
		writeError(http.StatusBadRequest, `value "address" cannot be empty`, w, r)
		return
	}
	if len(p) == 0 {
		writeError(http.StatusNotFound, msgNoProfile, w, r)
		return
	}
	if len(z) > 0 && q == nil {
		writeError(http.StatusNotFound, msgNoScript, w, r)
		return
	}
	i := strings.ToLower(n)
	l.RLock()
	_, ok := l.e[i]
	if l.RUnlock(); ok {
		writeError(http.StatusConflict, "listener already exists", w, r)
		return
	}
	x, err := p.Build()
	if err != nil {
		writeError(http.StatusInternalServerError, "profile build failed: "+err.Error(), w, r)
		return
	}
	d, err := l.s.Listen(i, b, x)
	if err != nil {
		writeError(http.StatusInternalServerError, "listener create failed: "+err.Error(), w, r)
		return
	}
	k := &listener{l: d, p: p, n: v, a: b, s: z}
	l.Lock()
	l.e[i] = k
	l.Unlock()
	l.events.publishListenerNew(i)
	writeListener(http.StatusCreated, w, k)
}
func (l *listenerManager) httpListenerPost(_ context.Context, w http.ResponseWriter, r *routex.Request, c routex.Content) {
	n := r.Values.StringDefault("name", "")
	if len(n) == 0 || !isValidName(n) {
		writeError(http.StatusBadRequest, `value "name" cannot be empty or invalid`, w, r)
		return
	}
	var (
		b      = c.StringDefault("address", "")
		p, v   = l.profile(c.StringDefault("profile", ""))
		q, err = c.String("script")
	)
	if len(b) == 0 {
		writeError(http.StatusBadRequest, `value "address" cannot be empty`, w, r)
		return
	}
	i := strings.ToLower(n)
	l.RLock()
	k, ok := l.e[i]
	if l.RUnlock(); !ok {
		writeError(http.StatusNotFound, msgNoListener, w, r)
		return
	}
	var (
		x c2.Profile
		h bool
	)
	// See if script is even set, since empty is OK
	if err == nil {
		if len(q) > 0 {
			// Empty script clears script, so it CAN be empty here, we're only
			// checking if it's a valid script.
			//
			// x is discarded, but q will be filled with the formatted string
			// name.
			var x *script
			if x, q = l.script(q); len(q) == 0 || x == nil {
				writeError(http.StatusNotFound, msgNoScript, w, r)
				return
			}
		}
		// Set to true to update script.
		h = true
	}
	if len(p) > 0 {
		if x, err = p.Build(); err != nil {
			writeError(http.StatusInternalServerError, "profile build failed: "+err.Error(), w, r)
			return
		}
	}
	if err = k.l.Replace(b, x); err != nil {
		writeError(http.StatusInternalServerError, "listener update failed: "+err.Error(), w, r)
		return
	}
	if len(p) > 0 {
		k.p, k.n = p, v
	}
	if h {
		k.s = q
	}
	l.events.publishListenerUpdate(i)
	writeListener(http.StatusOK, w, k)
}
func (l *listenerManager) httpListenerScriptPost(_ context.Context, w http.ResponseWriter, r *routex.Request, c routex.Content) {
	n := r.Values.StringDefault("name", "")
	if len(n) == 0 || !isValidName(n) {
		writeError(http.StatusBadRequest, `value "name" cannot be empty or invalid`, w, r)
		return
	}
	var (
		q = strings.ToLower(c.StringDefault("script", ""))
		i = strings.ToLower(n)
	)
	l.RLock()
	k, ok := l.e[i]
	if l.RUnlock(); !ok {
		writeError(http.StatusNotFound, msgNoListener, w, r)
		return
	}
	if len(q) > 0 {
		var x *script
		if x, q = l.script(q); len(q) == 0 || x == nil {
			writeError(http.StatusNotFound, msgNoScript, w, r)
			return
		}
	}
	k.s = q
	l.events.publishListenerUpdate(i)
	writeListener(http.StatusOK, w, k)
}
