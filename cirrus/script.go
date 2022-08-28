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
	"strconv"
	"strings"
	"sync"

	"github.com/PurpleSec/escape"
	"github.com/PurpleSec/routex"
	"github.com/PurpleSec/routex/val"
	"github.com/iDigitalFlame/xmt/c2/task"
	"github.com/iDigitalFlame/xmt/com"
	"github.com/iDigitalFlame/xmt/util/xerr"
)

const msgNoScript = "script was not found"

var (
	valScript = val.Set{
		val.Validator{Name: "data", Type: val.String, Optional: true},
		val.Validator{Name: "channel", Type: val.Bool, Optional: true},
		val.Validator{Name: "marks", Type: val.ListNumber, Optional: true},
		val.Validator{Name: "return_output", Type: val.Bool, Optional: true},
		val.Validator{Name: "stop_on_error", Type: val.Bool, Optional: true},
		val.Validator{Name: "commands", Type: val.ListString, Optional: true},
	}
	valScriptRollback = val.Set{
		val.Validator{Name: "pos", Type: val.Int, Optional: true, Rules: val.Rules{val.Positive}},
	}
	valScriptProxyDelete = val.Set{
		val.Validator{Name: "line", Type: val.String},
		val.Validator{Name: "proxy", Type: val.String, Rules: val.Rules{val.Length{Min: 1, Max: 256}}},
	}
	valScriptProxyAddUpdate = val.Set{
		val.Validator{Name: "line", Type: val.String},
		val.Validator{Name: "proxy", Type: val.String, Rules: val.Rules{val.Length{Min: 1, Max: 256}}},
		val.Validator{Name: "address", Type: val.String, Rules: val.Rules{val.Length{Min: 1, Max: 256}}},
		val.Validator{Name: "profile", Type: val.String, Rules: val.Rules{val.Length{Min: 1, Max: 256}}},
	}
)

type script struct {
	sync.Mutex
	s *task.Script
	c []string
	r []uint64
}
type scriptArgs struct {
	Data     *string   `json:"data"`
	Marks    *[]uint64 `json:"marks"`
	Output   *bool     `json:"return_output"`
	StopErr  *bool     `json:"stop_on_error"`
	Channel  *bool     `json:"channel"`
	Commands *[]string `json:"commands"`
}
type scriptManager struct {
	*Cirrus
	sync.RWMutex

	e map[string]*script
}

func (s *script) MarshalJSON() ([]byte, error) {
	s.Lock()
	b, err := json.Marshal(map[string]any{
		"marks":         s.r,                 // Required
		"script":        s.s.Payload(),       // Required
		"channel":       s.s.IsChannel(),     // Optional
		"commands":      s.c,                 // Required
		"return_output": s.s.IsOutput(),      // Optional
		"stop_on_error": s.s.IsStopOnError(), // Optional
	})
	s.Unlock()
	return b, err
}
func (s *script) UnmarshalJSON(b []byte) error {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(b, &m); err != nil {
		return err
	}
	var (
		t, ok = m["script"]
		v     bool
		k     []byte
	)
	if !ok {
		return xerr.New(`json: script is missing "script"`)
	}
	if err := json.Unmarshal(t, &k); err != nil {
		return err
	}
	s.Lock()
	defer s.Unlock()
	s.s = new(task.Script)
	s.s.Replace(k)
	k = nil
	if t, ok = m["marks"]; !ok {
		return xerr.New(`json: script is missing "marks"`)
	}
	if err := json.Unmarshal(t, &s.r); err != nil {
		return err
	}
	for i := range s.r {
		if s.r[i] <= uint64(s.s.Size()) {
			continue
		}
		return xerr.New(`json: script mark "` + strconv.FormatUint(s.r[i], 10) + "` is larger than the script size")
	}
	if t, ok = m["commands"]; !ok {
		return xerr.New(`json: script is missing "commands"`)
	}
	if err := json.Unmarshal(t, &s.c); err != nil {
		return err
	}
	if t, ok = m["channel"]; ok {
		if err := json.Unmarshal(t, &v); err != nil {
			return err
		}
		s.s.Channel(v)
	}
	if t, ok = m["return_output"]; ok {
		if err := json.Unmarshal(t, &v); err != nil {
			return err
		}
		s.s.Output(v)
	}
	if t, ok = m["stop_on_error"]; ok {
		if err := json.Unmarshal(t, &v); err != nil {
			return err
		}
		s.s.StopOnError(v)
	}
	return nil
}
func (c *Cirrus) script(n string) (*script, string) {
	if len(n) == 0 || !isValidName(n) {
		return nil, ""
	}
	v := strings.ToLower(n)
	c.scripts.RLock()
	x := c.scripts.e[v]
	c.scripts.RUnlock()
	return x, v
}
func (s *scriptManager) MarshalJSON() ([]byte, error) {
	s.Lock()
	b, err := json.Marshal(s.e)
	s.Unlock()
	return b, err
}
func (s *scriptManager) UnmarshalJSON(b []byte) error {
	var (
		m   map[string]*script
		err = json.Unmarshal(b, &m)
	)
	if err != nil {
		return err
	}
	s.Lock()
	for k, v := range m {
		if _, ok := s.e[k]; ok {
			continue
		}
		s.e[k] = v
	}
	s.Unlock()
	return nil
}
func (s *script) append(c string, n *com.Packet) error {
	s.Lock()
	if v := uint64(s.s.Size()); n == nil {
		if s.r = append(s.r, v); c[0] == 'c' {
			s.s.Channel(true)
		}
	} else {
		if err := s.s.Add(n); err != nil {
			s.Unlock()
			return err
		}
		s.r = append(s.r, v)
	}
	s.c = append(s.c, c)
	s.Unlock()
	return nil
}
func writeScriptReturn(w http.ResponseWriter, q *script) {
	if w.Write([]byte(`{"marks":[`)); len(q.r) > 0 {
		for i := range q.r {
			if i > 0 {
				w.Write([]byte{','})
			}
			w.Write([]byte(strconv.FormatUint(q.r[i], 10)))
		}
	}
	w.Write([]byte(`],"rollbacks":` + strconv.FormatUint(uint64(len(q.r)), 10) + `}`))
}
func writeScript(c int, w http.ResponseWriter, q *script) {
	if c > 0 {
		w.WriteHeader(c)
	}
	w.Write([]byte(`{"data":"`))
	writeBase64(w, q.s.Payload())
	w.Write([]byte(`","commands":[`))
	for i := range q.c {
		if i > 0 {
			w.Write([]byte{','})
		}
		w.Write([]byte(escape.JSON(q.c[i])))
	}
	w.Write([]byte{']', ','})
	if w.Write([]byte(`"marks":[`)); len(q.r) > 0 {
		for i := range q.r {
			if i > 0 {
				w.Write([]byte{','})
			}
			w.Write([]byte(strconv.FormatUint(q.r[i], 10)))
		}
	}
	w.Write([]byte(
		`],"rollbacks":` + strconv.FormatUint(uint64(len(q.r)), 10) + `,"stop_on_error":` +
			strconv.FormatBool(q.s.IsStopOnError()) + `,"return_output":` + strconv.FormatBool(q.s.IsOutput()) +
			`,"channel":` + strconv.FormatBool(q.s.IsChannel()) + `,"size":` + strconv.FormatUint(uint64(q.s.Size()), 10),
	))
	w.Write([]byte{'}'})
}
func (s *scriptManager) httpScriptGet(_ context.Context, w http.ResponseWriter, r *routex.Request) {
	q, _ := s.script(r.Values.StringDefault("name", ""))
	if q == nil {
		writeError(http.StatusNotFound, msgNoScript, w, r)
		return
	}
	writeScript(http.StatusOK, w, q)
}
func (s *scriptManager) httpScriptsGet(_ context.Context, w http.ResponseWriter, _ *routex.Request) {
	w.Write([]byte{'{'})
	if s.RLock(); len(s.e) > 0 {
		var n int
		for k, v := range s.e {
			if n > 0 {
				w.Write([]byte{','})
			}
			w.Write([]byte(escape.JSON(k) + `:`))
			writeScript(0, w, v)
			n++
		}
	}
	s.RUnlock()
	w.Write([]byte{'}'})
}
func (s *scriptManager) httpScriptDelete(_ context.Context, w http.ResponseWriter, r *routex.Request) {
	q, n := s.script(r.Values.StringDefault("name", ""))
	if q == nil {
		writeError(http.StatusNotFound, msgNoScript, w, r)
		return
	}
	q.s.Clear()
	q = nil
	s.Lock()
	s.e[n] = nil
	delete(s.e, n)
	s.Unlock()
	s.events.publishScriptDelete(n)
	w.WriteHeader(http.StatusOK)
}
func (s *scriptManager) httpScriptDLL(_ context.Context, w http.ResponseWriter, r *routex.Request, t taskDLL) {
	if len(t.Data) == 0 && len(t.Path) == 0 {
		writeError(http.StatusBadRequest, `specify a non-empty "data" or "path" value`, w, r)
		return
	}
	q, _ := s.script(r.Values.StringDefault("name", ""))
	if q == nil {
		writeError(http.StatusNotFound, msgNoScript, w, r)
		return
	}
	n, err := t.Packet()
	if err != nil {
		writeError(http.StatusInternalServerError, "task generation failed: "+err.Error(), w, r)
		return
	}
	q.append(t.Line, n)
	w.WriteHeader(http.StatusCreated)
	writeScriptReturn(w, q)
}
func (s *scriptManager) httpScriptPexec(_ context.Context, w http.ResponseWriter, r *routex.Request, t taskPull) {
	if len(t.URL) == 0 {
		writeError(http.StatusBadRequest, `invalid or empty "url" value`, w, r)
		return
	}
	q, _ := s.script(r.Values.StringDefault("name", ""))
	if q == nil {
		writeError(http.StatusNotFound, msgNoScript, w, r)
		return
	}
	q.append(t.Line, task.PullExecuteAgent(t.URL, t.Agent, t.Detach != boolTrue, t.Filter))
	w.WriteHeader(http.StatusCreated)
	writeScriptReturn(w, q)
}
func (s *scriptManager) httpScriptSpawn(_ context.Context, w http.ResponseWriter, r *routex.Request, t taskSpawn) {
	if len(t.Name) == 0 || !isValidName(t.Name) {
		writeError(http.StatusBadRequest, `invalid or empty "name" value`, w, r)
		return
	}
	q, _ := s.script(r.Values.StringDefault("name", ""))
	if q == nil {
		writeError(http.StatusNotFound, msgNoScript, w, r)
		return
	}
	p, _ := s.profile(t.Profile)
	if len(p) == 0 && len(t.Profile) > 0 {
		writeError(http.StatusNotFound, msgNoProfile, w, r)
		return
	}
	n, err := t.Packet(p)
	if err != nil {
		writeError(http.StatusBadRequest, err.Error(), w, r)
		return
	}
	q.append(t.Line, n)
	w.WriteHeader(http.StatusCreated)
	writeScriptReturn(w, q)
}
func (s *scriptManager) httpScriptZombie(_ context.Context, w http.ResponseWriter, r *routex.Request, t taskZombie) {
	if len(t.Data) == 0 {
		writeError(http.StatusBadRequest, `invalid or empty "data" value`, w, r)
		return
	}
	if len(t.Fake) == 0 {
		writeError(http.StatusBadRequest, `invalid or empty "fake" value`, w, r)
		return
	}
	q, _ := s.script(r.Values.StringDefault("name", ""))
	if q == nil {
		writeError(http.StatusNotFound, msgNoScript, w, r)
		return
	}
	n, err := t.Packet()
	if err != nil {
		writeError(http.StatusInternalServerError, "task generation failed: "+err.Error(), w, r)
		return
	}
	q.append(t.Line, n)
	w.WriteHeader(http.StatusCreated)
	writeScriptReturn(w, q)
}
func (s *scriptManager) httpScriptSystem(_ context.Context, w http.ResponseWriter, r *routex.Request, t taskSystem) {
	if len(t.Command) == 0 {
		writeError(http.StatusBadRequest, `invalid or empty "command" value`, w, r)
		return
	}
	q, _ := s.script(r.Values.StringDefault("name", ""))
	if q == nil {
		writeError(http.StatusNotFound, msgNoScript, w, r)
		return
	}
	n, err := syscallPacket(t.Command, t.Args, t.Filter)
	if err != nil {
		writeError(http.StatusInternalServerError, "task generation failed: "+err.Error(), w, r)
		return
	}
	if n == nil {
		q.s.Channel(isTrue(t.Args))
		w.WriteHeader(http.StatusOK)
		return
	}
	q.append(t.Line, n)
	w.WriteHeader(http.StatusCreated)
	writeScriptReturn(w, q)
}
func (s *scriptManager) httpScriptPutPost(_ context.Context, w http.ResponseWriter, r *routex.Request, a scriptArgs) {
	q, n := s.script(r.Values.StringDefault("name", ""))
	switch {
	case q != nil && r.IsPut():
		writeError(http.StatusConflict, "script already exists", w, r)
		return
	case q == nil && r.IsPost():
		writeError(http.StatusNotFound, msgNoScript, w, r)
		return
	}
	if a.Data == nil && a.Marks != nil && len(*a.Marks) > 0 {
		writeError(http.StatusBadRequest, `"marks" cannot be specified without data`, w, r)
		return
	}
	var (
		b []byte
		m []uint64
	)
	if a.Data != nil {
		var err error
		if b, err = readEmptyB64(*a.Data); err != nil {
			writeError(http.StatusBadRequest, err.Error(), w, r)
			return
		}
	}
	if a.Marks != nil && len(*a.Marks) > 0 {
		for _, v := range *a.Marks {
			if v <= uint64(len(b)) {
				continue
			}
			writeError(http.StatusBadRequest, `"marks" value "`+strconv.FormatUint(v, 10)+`" is larger than supplied data size`, w, r)
			return
		}
		m = make([]uint64, len(*a.Marks))
		copy(m, *a.Marks)
	} else {
		m = []uint64{0}
	}
	if q == nil {
		q = &script{s: new(task.Script)}
	}
	if q.Lock(); a.Data != nil {
		q.s.Replace(b)
		q.r = m
	}
	if a.Commands != nil {
		q.c = *a.Commands
	}
	if a.Output != nil {
		q.s.Output(*a.Output)
	}
	if a.StopErr != nil {
		q.s.StopOnError(*a.StopErr)
	}
	if a.Channel != nil {
		q.s.Channel(*a.Channel)
	}
	if q.Unlock(); r.IsPost() {
		s.events.publishScriptUpdate(n)
		writeScript(http.StatusOK, w, q)
		return
	}
	s.Lock()
	s.e[n] = q
	s.Unlock()
	s.events.publishScriptNew(n)
	writeScript(http.StatusCreated, w, q)
}
func (s *scriptManager) httpScriptCommand(_ context.Context, w http.ResponseWriter, r *routex.Request, t taskCommand) {
	if len(t.Command) == 0 {
		writeError(http.StatusBadRequest, `invalid or empty "command" value`, w, r)
		return
	}
	q, _ := s.script(r.Values.StringDefault("name", ""))
	if q == nil {
		writeError(http.StatusNotFound, msgNoScript, w, r)
		return
	}
	n, err := t.Packet()
	if err != nil {
		writeError(http.StatusInternalServerError, "task generation failed: "+err.Error(), w, r)
		return
	}
	q.append(t.Line, n)
	w.WriteHeader(http.StatusCreated)
	writeScriptReturn(w, q)
}
func (s *scriptManager) httpScriptPull(_ context.Context, w http.ResponseWriter, r *routex.Request, c routex.Content) {
	var (
		u = c.StringDefault("url", "")
		p = c.StringDefault("path", "")
		a = c.StringDefault("agent", "")
	)
	if len(p) == 0 {
		writeError(http.StatusBadRequest, `invalid or empty "url" value`, w, r)
		return
	}
	if len(p) == 0 {
		writeError(http.StatusBadRequest, `invalid or empty "path" value`, w, r)
		return
	}
	q, _ := s.script(r.Values.StringDefault("name", ""))
	if q == nil {
		writeError(http.StatusNotFound, msgNoScript, w, r)
		return
	}
	q.append(c.StringDefault("line", ""), task.PullAgent(u, a, p))
	w.WriteHeader(http.StatusCreated)
	writeScriptReturn(w, q)
}
func (s *scriptManager) httpScriptMigrate(_ context.Context, w http.ResponseWriter, r *routex.Request, t taskMigrate) {
	if len(t.Name) == 0 || !isValidName(t.Name) {
		writeError(http.StatusBadRequest, `invalid or empty "name" value`, w, r)
		return
	}
	q, _ := s.script(r.Values.StringDefault("name", ""))
	if q == nil {
		writeError(http.StatusNotFound, msgNoScript, w, r)
		return
	}
	p, _ := s.profile(t.Profile)
	if len(p) == 0 && len(t.Profile) > 0 {
		writeError(http.StatusNotFound, msgNoProfile, w, r)
		return
	}
	n, err := t.Packet(p)
	if err != nil {
		writeError(http.StatusBadRequest, err.Error(), w, r)
		return
	}
	q.append(t.Line, n)
	w.WriteHeader(http.StatusCreated)
	writeScriptReturn(w, q)
}
func (s *scriptManager) httpScriptNote(_ context.Context, w http.ResponseWriter, r *routex.Request, c routex.Content) {
	v := c.StringDefault("line", "")
	if len(v) == 0 {
		writeError(http.StatusBadRequest, `invalid or empty "line" value`, w, r)
		return
	}
	q, _ := s.script(r.Values.StringDefault("name", ""))
	if q == nil {
		writeError(http.StatusNotFound, msgNoScript, w, r)
		return
	}
	q.append(v, nil)
	w.WriteHeader(http.StatusOK)
	writeScriptReturn(w, q)
}
func (s *scriptManager) httpScriptLogin(_ context.Context, w http.ResponseWriter, r *routex.Request, c routex.Content) {
	u := c.StringDefault("user", "")
	if len(u) == 0 {
		writeError(http.StatusBadRequest, `specify a non-empty "user" value`, w, r)
		return
	}
	q, _ := s.script(r.Values.StringDefault("name", ""))
	if q == nil {
		writeError(http.StatusNotFound, msgNoScript, w, r)
		return
	}
	var (
		p = c.StringDefault("pass", "")
		d = c.StringDefault("domain", "")
	)
	q.append(c.StringDefault("line", ""), task.LoginUser(u, d, p))
	w.WriteHeader(http.StatusCreated)
	writeScriptReturn(w, q)
}
func (s *scriptManager) httpScriptAssembly(_ context.Context, w http.ResponseWriter, r *routex.Request, t taskAssembly) {
	if len(t.Data) == 0 {
		writeError(http.StatusBadRequest, `invalid or empty "data" value`, w, r)
		return
	}
	q, _ := s.script(r.Values.StringDefault("name", ""))
	if q == nil {
		writeError(http.StatusNotFound, msgNoScript, w, r)
		return
	}
	n, err := t.Packet()
	if err != nil {
		writeError(http.StatusInternalServerError, "task generation failed: "+err.Error(), w, r)
		return
	}
	q.append(t.Line, n)
	w.WriteHeader(http.StatusCreated)
	writeScriptReturn(w, q)
}
func (s *scriptManager) httpScriptUpload(_ context.Context, w http.ResponseWriter, r *routex.Request, c routex.Content) {
	p := c.StringDefault("path", "")
	if len(p) == 0 {
		writeError(http.StatusBadRequest, `invalid or empty "path" value`, w, r)
		return
	}
	q, _ := s.script(r.Values.StringDefault("name", ""))
	if q == nil {
		writeError(http.StatusNotFound, msgNoScript, w, r)
		return
	}
	b, err := readEmptyB64(c.StringDefault("data", ""))
	if err != nil {
		writeError(http.StatusBadRequest, err.Error(), w, r)
		return
	}
	q.append(c.StringDefault("line", ""), task.Upload(p, b))
	w.WriteHeader(http.StatusCreated)
	writeScriptReturn(w, q)
}
func (s *scriptManager) httpScriptProfile(_ context.Context, w http.ResponseWriter, r *routex.Request, c routex.Content) {
	q, _ := s.script(r.Values.StringDefault("name", ""))
	if q == nil {
		writeError(http.StatusNotFound, msgNoScript, w, r)
		return
	}
	p, _ := s.profile(c.StringDefault("profile", ""))
	if len(p) == 0 {
		writeError(http.StatusNotFound, msgNoProfile, w, r)
		return
	}
	q.append(c.StringDefault("line", ""), task.Profile(p))
	w.WriteHeader(http.StatusCreated)
	writeScriptReturn(w, q)
}
func (s *scriptManager) httpScriptDownload(_ context.Context, w http.ResponseWriter, r *routex.Request, c routex.Content) {
	p := c.StringDefault("path", "")
	if len(p) == 0 {
		writeError(http.StatusBadRequest, `invalid or empty "path" value`, w, r)
		return
	}
	q, _ := s.script(r.Values.StringDefault("name", ""))
	if q == nil {
		writeError(http.StatusNotFound, msgNoScript, w, r)
		return
	}
	q.append(c.StringDefault("line", ""), task.Download(p))
	w.WriteHeader(http.StatusCreated)
	writeScriptReturn(w, q)
}
func (s *scriptManager) httpScriptRegistry(_ context.Context, w http.ResponseWriter, r *routex.Request, c routex.Content) {
	var (
		k = c.StringDefault("key", "")
		v = c.StringDefault("value", "")
		a = c.StringDefault("action", "")
	)
	if len(k) == 0 || len(a) == 0 {
		writeError(http.StatusBadRequest, `specify a non-empty "key" and "action" value`, w, r)
		return
	}
	q, _ := s.script(r.Values.StringDefault("name", ""))
	if q == nil {
		writeError(http.StatusNotFound, msgNoScript, w, r)
		return
	}
	n, err := registryPacket(c, a, k, v)
	if err != nil {
		writeError(http.StatusBadRequest, err.Error(), w, r)
		return
	}
	q.append(c.StringDefault("line", ""), n)
	w.WriteHeader(http.StatusCreated)
	writeScriptReturn(w, q)
}
func (s *scriptManager) httpScriptSystemIo(_ context.Context, w http.ResponseWriter, r *routex.Request, c routex.Content) {
	a := c.StringDefault("action", "")
	if len(a) == 0 {
		writeError(http.StatusBadRequest, `specify a non-empty "action" value`, w, r)
		return
	}
	q, _ := s.script(r.Values.StringDefault("name", ""))
	if q == nil {
		writeError(http.StatusNotFound, msgNoScript, w, r)
		return
	}
	n, _, err := ioPacket(c, a)
	if err != nil {
		writeError(http.StatusBadRequest, err.Error(), w, r)
		return
	}
	q.append(c.StringDefault("line", ""), n)
	w.WriteHeader(http.StatusCreated)
	writeScriptReturn(w, q)
}
func (s *scriptManager) httpScriptWindowUI(_ context.Context, w http.ResponseWriter, r *routex.Request, c routex.Content) {
	a := c.StringDefault("action", "")
	if len(a) == 0 {
		writeError(http.StatusBadRequest, `specify a non-empty "action" value`, w, r)
		return
	}
	q, _ := s.script(r.Values.StringDefault("name", ""))
	if q == nil {
		writeError(http.StatusNotFound, msgNoScript, w, r)
		return
	}
	n, _, err := uiPacket(c, a)
	if err != nil {
		writeError(http.StatusBadRequest, err.Error(), w, r)
		return
	}
	q.append(c.StringDefault("line", ""), n)
	w.WriteHeader(http.StatusCreated)
	writeScriptReturn(w, q)
}
func (s *scriptManager) httpScriptRollback(_ context.Context, w http.ResponseWriter, r *routex.Request, c routex.Content) {
	q, _ := s.script(r.Values.StringDefault("name", ""))
	if q == nil {
		writeError(http.StatusNotFound, msgNoScript, w, r)
		return
	}
	q.Lock()
	h := len(q.r) > 0
	if q.Unlock(); !h {
		writeError(http.StatusNotFound, "no rollback points avaliable", w, r)
		return
	}
	p, ok := c.Uint("pos")
	if q.Lock(); ok != nil {
		p = uint64(len(q.r) - 1)
	}
	if err := q.s.Truncate(int(q.r[p])); err != nil {
		q.Unlock()
		writeError(http.StatusBadRequest, err.Error(), w, r)
		return
	}
	if q.r = q.r[:p]; uint64(len(q.c)) > p {
		q.c = q.c[:p]
	}
	q.Unlock()
	writeScript(http.StatusOK, w, q)
}
func (s *scriptManager) httpScriptProxyDelete(_ context.Context, w http.ResponseWriter, r *routex.Request, c routex.Content) {
	q, _ := s.script(r.Values.StringDefault("name", ""))
	if q == nil {
		writeError(http.StatusNotFound, msgNoScript, w, r)
		return
	}
	n := c.StringDefault("proxy", "")
	if !isValidName(n) {
		writeError(http.StatusBadRequest, `value "proxy" cannot be invalid`, w, r)
		return
	}
	q.append(c.StringDefault("line", ""), task.ProxyRemove(n))
	w.WriteHeader(http.StatusCreated)
	writeScriptReturn(w, q)
}
func (s *scriptManager) httpScriptProxyPutPost(_ context.Context, w http.ResponseWriter, r *routex.Request, c routex.Content) {
	q, _ := s.script(r.Values.StringDefault("name", ""))
	if q == nil {
		writeError(http.StatusNotFound, msgNoScript, w, r)
		return
	}
	n := r.Values.StringDefault("proxy", "")
	if !isValidName(n) {
		writeError(http.StatusBadRequest, `value "proxy" cannot be invalid`, w, r)
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
	if r.IsPost() {
		q.append(c.StringDefault("line", ""), task.ProxyReplace(strings.ToLower(n), b, p))
	} else {
		q.append(c.StringDefault("line", ""), task.Proxy(strings.ToLower(n), b, p))
	}
	w.WriteHeader(http.StatusCreated)
	writeScriptReturn(w, q)
}
