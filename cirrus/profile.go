package cirrus

import (
	"context"
	"encoding/base64"
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

func (c *Cirrus) profile(n string) cfg.Config {
	if len(n) == 0 || !isValidName(n) {
		return nil
	}
	c.profiles.RLock()
	v, ok := c.profiles.e[strings.ToLower(n)]
	if c.profiles.RUnlock(); !ok {
		return nil
	}
	return v
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
	v := p.profile(r.Values.StringDefault("name", ""))
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
	v := p.profile(n)
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
	w.Write([]byte(`{"result":` + escape.JSON(c.String()) + `}`))
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
	var (
		n = r.Values.StringDefault("name", "")
		v = p.profile(n)
	)
	if len(v) == 0 {
		writeError(http.StatusNotFound, msgNoProfile, w, r)
		return
	}
	c, err := readProfileFromBody(r.Body)
	if v = nil; err != nil {
		writeError(http.StatusBadRequest, err.Error(), w, r)
		return
	}
	i := strings.ToLower(n)
	p.Lock()
	p.e[i] = c
	p.Unlock()
	p.events.publishProfileUpdate(i)
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"result":` + escape.JSON(c.String()) + `}`))
}
func (p *profileManager) httpProfileDelete(_ context.Context, w http.ResponseWriter, r *routex.Request) {
	var (
		n = r.Values.StringDefault("name", "")
		v = p.profile(n)
	)
	if len(v) == 0 {
		writeError(http.StatusNotFound, msgNoProfile, w, r)
		return
	}
	v = nil
	i := strings.ToLower(n)
	p.Lock()
	p.e[i] = nil
	delete(p.e, i)
	p.Unlock()
	p.events.publishProfileDelete(i)
	w.WriteHeader(http.StatusOK)
}
