package cirrus

import (
	"context"
	"net/http"
	"strings"
	"sync"

	"github.com/PurpleSec/escape"
	"github.com/PurpleSec/routex"
	"github.com/PurpleSec/routex/val"
	"github.com/iDigitalFlame/xmt/c2"
	"github.com/iDigitalFlame/xmt/c2/cfg"
)

const msgNoListener = "listener was not found"

var valListener = val.Set{
	val.Validator{Name: "address", Type: val.String, Rules: val.Rules{val.Length{Min: 1, Max: 256}}},
	val.Validator{Name: "profile", Type: val.String, Rules: val.Rules{val.Length{Min: 1, Max: 256}}},
}

type listener struct {
	l *c2.Listener
	n string
	p cfg.Config
}
type listenerManager struct {
	*Cirrus
	sync.RWMutex

	e map[string]*listener
}

func writeListener(c int, w http.ResponseWriter, l *listener) {
	if c > 0 {
		w.WriteHeader(c)
	}
	w.Write([]byte(`{"profile_name":` + escape.JSON(l.n) + `,"profile":"`))
	writeBase64(w, l.p.Bytes())
	w.Write([]byte(`","listener":`))
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
		b = c.StringDefault("address", "")
		v = c.StringDefault("profile", "")
		p = l.profile(v)
	)
	if len(b) == 0 {
		writeError(http.StatusBadRequest, `value "address" cannot be empty`, w, r)
		return
	}
	if len(p) == 0 {
		writeError(http.StatusBadRequest, msgNoProfile, w, r)
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
	k := &listener{l: d, p: p, n: strings.ToLower(v)}
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
		b = c.StringDefault("address", "")
		v = c.StringDefault("profile", "")
		p = l.profile(v)
	)
	if len(b) == 0 {
		writeError(http.StatusBadRequest, `value "address" cannot be empty`, w, r)
		return
	}
	if len(p) == 0 {
		writeError(http.StatusBadRequest, msgNoProfile, w, r)
		return
	}
	i := strings.ToLower(n)
	l.RLock()
	k, ok := l.e[i]
	if l.RUnlock(); !ok {
		writeError(http.StatusNotFound, msgNoListener, w, r)
		return
	}
	x, err := p.Build()
	if err != nil {
		writeError(http.StatusInternalServerError, "profile build failed: "+err.Error(), w, r)
		return
	}
	if err = k.l.Replace(b, x); err != nil {
		writeError(http.StatusInternalServerError, "listener update failed: "+err.Error(), w, r)
		return
	}
	k.p, k.n = p, strings.ToLower(v)
	l.events.publishListenerUpdate(i)
	writeListener(http.StatusOK, w, k)
}
