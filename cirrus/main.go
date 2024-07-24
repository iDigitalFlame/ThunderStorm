// Copyright (C) 2020 - 2024 iDigitalFlame
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
	"flag"
	"net/http"
	"os"
	"path/filepath"
	"syscall"

	"github.com/PurpleSec/logx"
	"github.com/iDigitalFlame/xmt/c2"
	"github.com/iDigitalFlame/xmt/com/limits"
	"github.com/iDigitalFlame/xmt/util/text"
)

var version = "unknown"

const usage = ` Cirrus: ThunderStorm C2/Rest Engine
Part of the |||||| ThunderStorm Project (https://dij.sh/ts)
(c) 2019 - 2023 iDigitalFlame

Usage: cirrus -b <bind_address:port> [-p password] [-no-auth] [-f data_file] [-l log_file] [-n log_level] [-c csv_output] [-t tracker]

Required Arguments:
  -b <bind_address:port>        Specify a "address:port" that the ReST API will
                                  be bound to.

Optional Arguments:
  -p <password>                 Specify a password to be used in the "X-CirrusAuth"
                                  HTTP header for connections. If this is empty, and
                                  the "-no-auth" argument is not specified, a random
                                  password will be generated for you and printed to
                                  stdout during startup. If a password was specified
                                  in the "data_file" argument, this can be omitted to
                                  use that instead.
  -no-auth                      Argument that can be used to force Cirrus to NOT
                                  validate connections with a password. If a password
                                  is specified with "-p", this argument is ignored.
                                  However, this value will take precedence over any
                                  passwords saved in the "data_file".
  -f <data_file>                Path to a file to be used as the backing store for
                                  Cirrus. This can be used to save/load the contents
                                  and state during startup/shutdown for Scripts,
                                  Profiles and Listeners. This defaults to "${pwd}/cirrus.json"
                                  if omitted.
  -V                            Print version string and exit.

 Tracking/Event Arguments:
  -c <csv_output>               Specify a file path for a CSV file to capture/log
                                  all C2 events. If the file already exists, it will
                                  be appended to.
  -t <tracker>                  Specify a file path to be used for tracking updates.
                                  This file will be cleared and rewritten with
                                  statistics every minute.

 Logging Arguments:
  -l <log_file>                 Path to a log file to write to for the C2 log. If
                                  no path is specified or this argument is ignored,
                                  stdout will be used instead.
  -n <log_level [0-5]>          Specify the log level to be used when logging for
                                  the C2 log. By default, or if unspecified, this
                                  will default ton Informational (2). Values 0-5
                                  are valid, anything else will default to
                                  Informational (2). Values are 0: Trace, 1:Debug,
                                  2:Informational, 3:Warning, 4: Error, 5:Fatal.
  -o <log_file>                 Path to a log file to write to for the CIRRUS log.
                                  If no path is specified or this argument is ignored,
                                  stdout will be used instead.
  -k <log_level [0-5]>          Specify the log level to be used when logging for
                                  the CIRRUS log. By default, or if unspecified, this
                                  will default ton Informational (2). Values 0-5
                                  are valid, anything else will default to
                                  Warning (3). Values are 0: Trace, 1:Debug,
                                  2:Informational, 3:Warning, 4: Error, 5:Fatal.
`

// Cmdline will attempt to build and run a Cirrus instance. This function
// will block until completion.
func Cmdline() {
	var (
		p, b, l, c, t, d, y string
		n, h                bool
		e, k                int
		err                 error
		f                   = flag.NewFlagSet("", flag.ContinueOnError)
	)
	f.Usage = func() {
		os.Stdout.WriteString(usage)
		os.Exit(2)
	}
	f.StringVar(&p, "p", "", "")
	f.StringVar(&b, "b", "", "")
	f.StringVar(&l, "l", "", "")
	f.StringVar(&c, "c", "", "")
	f.StringVar(&t, "t", "", "")
	f.StringVar(&d, "f", "", "")
	f.StringVar(&y, "o", "", "")
	f.BoolVar(&h, "V", false, "")
	f.BoolVar(&n, "no-auth", false, "")
	f.IntVar(&e, "n", int(logx.Info), "")
	f.IntVar(&k, "k", int(logx.Warning), "")
	switch err = f.Parse(os.Args[1:]); err {
	case nil:
		if h {
			os.Stdout.WriteString("Cirrus: " + version + "\n")
			os.Exit(0)
		}
		if len(b) == 0 {
			f.Usage()
		}
	case flag.ErrHelp:
		f.Usage()
	default:
		os.Stderr.WriteString("Error " + err.Error() + "!\n")
		os.Exit(1)
	}

	var logC2, logCirrus logx.Log
	if len(l) > 0 {
		if logC2, err = logx.File(l, logx.Normal(e, logx.Info), logx.Append); err != nil {
			os.Stderr.WriteString("Error " + err.Error() + "!\n")
			os.Exit(1)
		}
	} else {
		logC2 = logx.Console(logx.Normal(e, logx.Info))
	}
	if len(y) > 0 {
		if logCirrus, err = logx.File(y, logx.Normal(k, logx.Warning), logx.Append); err != nil {
			os.Stderr.WriteString("Error " + err.Error() + "!\n")
			os.Exit(1)
		}
	} else {
		if k == int(logx.Warning) {
			logCirrus = logC2
		} else {
			logCirrus = logx.Console(logx.Normal(k, logx.Warning))
		}
	}

	var (
		x, q = context.WithCancel(context.Background())
		i    = c2.NewServerContext(x, logC2)
		a    = NewContext(x, i, logCirrus, "")
	)
	if len(d) == 0 {
		if d, err = os.Getwd(); err != nil {
			d = "cirrus.json"
		} else {
			d = filepath.Join(d, "cirrus.json")
		}
	}

	logCirrus.Info(`[cirrus] Loading config from "%s"..`, d)
	if err = a.Load(d); err != nil {
		q()
		a.Close()
		i.Close()
		logCirrus.Error(`[cirrus] Load from "%s" error: %s!`, d, err.Error())
		os.Exit(1)
	}

	switch {
	case len(a.Auth) == 0 && n:
	case len(a.Auth) == 0 && !n && len(p) > 0:
		a.Auth = p
	case len(a.Auth) == 0 && !n && len(p) == 0:
		a.Auth = text.All.String(16)
		os.Stdout.WriteString("Generated authentication password: " + a.Auth + "\n")
	}

	if err = a.TrackStats(c, t); err != nil {
		a.Close()
		i.Close()
		logCirrus.Error(`[cirrus] TrackStats error: %s!`, err.Error())
		os.Exit(1)
	}

	logCirrus.Info(`[cirrus] Started on "%s"!`, b)
	go func() {
		if err = a.Listen(b); err != http.ErrServerClosed && err != nil {
			logCirrus.Error(`[cirrus] Error durring startup: %s!`, err.Error())
		}
		q()
	}()

	var (
		w = make(chan os.Signal, 1)
		v = make(chan os.Signal, 1)
	)
	limits.MemorySweep(x)
	limits.Notify(v, syscall.SIGHUP)
	limits.Notify(w, syscall.SIGINT, syscall.SIGQUIT, syscall.SIGTERM)
loop:
	for {
		select {
		case <-v:
			logCirrus.Info(`[cirrus] SIGHUP Received, saving to %q.`, d)
			if err = a.Save(d); err != nil {
				logCirrus.Error(`[cirrus] Save to "%s" failed: %s!`, d, err.Error())
			}
		case <-w:
			break loop
		case <-x.Done():
			break loop
		case <-i.Done():
			break loop
		}
	}
	if q(); len(d) > 0 {
		if err = a.Save(d); err != nil {
			logCirrus.Error(`[cirrus] Save to "%s" failed: %s!`, d, err.Error())
		}
	}
	logCirrus.Info("[cirrus] Shutting down!")
	a.Close()
	i.Close()
	close(w)
	close(v)
}
