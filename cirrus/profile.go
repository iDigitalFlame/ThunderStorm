// Copyright (C) 2020 - 2023 iDigitalFlame
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
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync"

	"github.com/PurpleSec/escape"
	"github.com/PurpleSec/routex"
	"github.com/iDigitalFlame/xmt/c2/cfg"
	"github.com/iDigitalFlame/xmt/util/xerr"
)

const msgNoProfile = "profile was not found"

type profileManager struct {
	*Cirrus
	sync.RWMutex

	e map[string]cfg.Config
}

func (p *profileManager) MarshalJSON() ([]byte, error) {
	p.Lock()
	m := make(map[string][]byte, len(p.e))
	for k, v := range p.e {
		m[k] = v
	}
	p.Unlock()
	return json.Marshal(m)
}
func (p *profileManager) UnmarshalJSON(b []byte) error {
	var m map[string][]byte
	if err := json.Unmarshal(b, &m); err != nil {
		return err
	}
	p.Lock()
	for k, v := range m {
		p.e[k] = v
	}
	p.Unlock()
	return nil
}
func (c *Cirrus) profile(n string) (cfg.Config, string) {
	if len(n) == 0 || !isValidName(n) {
		return nil, ""
	}
	i := strings.ToLower(n)
	c.profiles.RLock()
	v, ok := c.profiles.e[i]
	if c.profiles.RUnlock(); !ok {
		return nil, ""
	}
	return v, i
}
func readProfileFromBody(r io.ReadCloser) (cfg.Config, error) {
	var (
		d      = base64.NewDecoder(base64.StdEncoding, r)
		b, err = io.ReadAll(d)
	)
	if r.Close(); err != nil {
		return nil, xerr.New("profile decode failed: " + err.Error())
	}
	if len(b) == 0 {
		return nil, xerr.New("profile is empty")
	}
	c := cfg.Config(b)
	if err = c.Validate(); err != nil {
		return nil, xerr.New("profile is invalid: " + err.Error())
	}
	return c, nil
}
func (p *profileManager) httpProfileGet(_ context.Context, w http.ResponseWriter, r *routex.Request) {
	v, _ := p.profile(r.Values.StringDefault("name", ""))
	if len(v) == 0 {
		writeError(http.StatusNotFound, msgNoProfile, w, r)
		return
	}
	w.WriteHeader(http.StatusOK)
	writeBase64(w, v)
}
func (p *profileManager) httpProfilePut(_ context.Context, w http.ResponseWriter, r *routex.Request) {
	n := r.Values.StringDefault("name", "")
	if len(n) == 0 || !isValidName(n) {
		writeError(http.StatusBadRequest, "profile name is invalid", w, r)
		return
	}
	v, _ := p.profile(n)
	if len(v) > 0 {
		writeError(http.StatusConflict, "profile already exists", w, r)
		return
	}
	c, err := readProfileFromBody(r.Body)
	if err != nil {
		writeError(http.StatusBadRequest, err.Error(), w, r)
		return
	}
	i := strings.ToLower(n)
	p.Lock()
	p.e[i] = c
	p.Unlock()
	p.events.publishProfileNew(i)
	w.WriteHeader(http.StatusCreated)
	w.Write([]byte(`{"result":"` + c.String() + `"}`))
}
func (p *profileManager) httpProfilesGet(_ context.Context, w http.ResponseWriter, _ *routex.Request) {
	p.RLock()
	if w.Write([]byte{'{'}); len(p.e) > 0 {
		var n int
		for k, v := range p.e {
			if len(k) == 0 || len(v) == 0 {
				continue
			}
			if n > 0 {
				w.Write([]byte{','})
			}
			w.Write([]byte(escape.JSON(k) + `:"` + base64.StdEncoding.EncodeToString(v) + `"`))
			n++
		}
	}
	p.RUnlock()
	w.Write([]byte{'}'})
}
func (p *profileManager) httpProfilePost(_ context.Context, w http.ResponseWriter, r *routex.Request) {
	v, n := p.profile(r.Values.StringDefault("name", ""))
	if len(v) == 0 {
		writeError(http.StatusNotFound, msgNoProfile, w, r)
		return
	}
	c, err := readProfileFromBody(r.Body)
	if v = nil; err != nil {
		writeError(http.StatusBadRequest, err.Error(), w, r)
		return
	}
	p.Lock()
	p.e[n] = c
	p.Unlock()
	p.events.publishProfileUpdate(n)
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"result":"` + c.String() + `"}`))
}
func (p *profileManager) httpProfileDelete(_ context.Context, w http.ResponseWriter, r *routex.Request) {
	v, n := p.profile(r.Values.StringDefault("name", ""))
	if len(v) == 0 {
		writeError(http.StatusNotFound, msgNoProfile, w, r)
		return
	}
	v = nil
	p.Lock()
	p.e[n] = nil
	delete(p.e, n)
	p.Unlock()
	p.events.publishProfileDelete(n)
	w.WriteHeader(http.StatusOK)
}
