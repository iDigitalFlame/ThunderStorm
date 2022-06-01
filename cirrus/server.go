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

const usage = ` Cirrus: ThunderStorm C2/Rest Engine
Part of the |||||| ThunderStorm Project (https://dij.sh/ts)
(c) 2019 - 2022 iDigitalFlame

Usage: cirrus -b <bind_address:port> [-p password] [-no-auth] [-f data_file] [-l log_file] [-n log_level] [-c csv_output] [-t tracker]

Required Arguments:
  -b <bind_address:port>        Specify a "address:port" that the ReST API will
                                 be bound to.

Optional Arguments:
  -p <password>                 Specify a password to be used in the "X-CirrusAuth"
                                 HTTP header for connections. If this is empty, and
                                 the "-no-auth" argument is not specified, a random
                                 password will be generated for you and printed to
                                 stdout during startup.
  -no-auth                      Argument that can be used to force Cirrus to NOT
                                 validate connections with a password. If a password
                                 is specified with "-p", this argument is ignored.
  -f <data_file>                Path to a file to be used as the backing store for
                                 Cirrus. This can be used to save/load the contents
                                 and state during startup/shutdown for Scripts, Profiles
                                 and Listeners. This defaults to "${pwd}/cirrus.json" if
                                 omitted.
  -l <log_file>                 Path to a log file to write to. If no path is
                                 specified or this argument is ignored, stdout will
                                 be used instead.
  -n <log_level [0-5]>          Specify the log level to be used when logging. By
                                 default, or if unspecified, this will default to
                                 Informational (2). Values 0-5 are valid, anything
                                 else will default to Informational (2). Values are
                                 0: Trace, 1:Debug, 2:Informational, 3:Warning,
                                 4: Error, 5:Fatal.
  -c <csv_output>               Specify a file path for a CSV file to capture/log
                                 all C2 events. If the file already exists, it will
                                 be appended to.
  -t <tracker>                  Specify a file path to be used for tracking updates.
                                 This file will be cleared and rewritten with
                                 statistics every minute.
`

// Cmdline will attempt to build and run a Cirrus instance. This function
// will block until completion.
func Cmdline() {
	var (
		p, b, l, c, t, d string
		n                bool
		e                int
		err              error
		f                = flag.NewFlagSet("", flag.ContinueOnError)
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
	f.BoolVar(&n, "no-auth", false, "")
	f.IntVar(&e, "n", int(logx.Info), "")

	switch err = f.Parse(os.Args[1:]); err {
	case nil:
	case flag.ErrHelp:
		f.Usage()
	default:
		os.Stderr.WriteString("Error " + err.Error() + "!\n")
		os.Exit(1)
	}

	if len(b) == 0 {
		f.Usage()
	}

	var log logx.Log
	if len(l) > 0 {
		if log, err = logx.File(l, logx.Normal(e, logx.Info), logx.Append); err != nil {
			os.Stderr.WriteString("Error " + err.Error() + "!\n")
			os.Exit(1)
		}
	} else {
		log = logx.Console(logx.Normal(e, logx.Info))
	}

	if len(p) == 0 && !n {
		p = text.All.String(16)
		os.Stdout.WriteString("Generated authentication password: " + p + "\n")
	}

	var (
		x, q = context.WithCancel(context.Background())
		i    = c2.NewServerContext(x, log)
		a    = NewContext(x, i, p)
	)

	if len(d) == 0 {
		if d, err = os.Getwd(); err != nil {
			d = "cirrus.json"
		} else {
			d = filepath.Join(d, "cirrus.json")
		}
	}

	if err = a.Load(d); err != nil {
		a.Close()
		i.Close()
		os.Stderr.WriteString("Error " + err.Error() + "!\n")
		os.Exit(1)
	}

	if err = a.TrackStats(c, t); err != nil {
		a.Close()
		i.Close()
		os.Stderr.WriteString("Error " + err.Error() + "!\n")
		os.Exit(1)
	}

	log.Info("Cirrus started on %q!", b)
	go func() {
		if err = a.Listen(b); err != http.ErrServerClosed && err != nil {
			os.Stderr.WriteString("Error during start up: " + err.Error() + "!\n")
		}
		q()
	}()

	w := make(chan os.Signal, 1)
	limits.MemorySweep(x)
	limits.Notify(w, syscall.SIGINT, syscall.SIGQUIT, syscall.SIGTERM, syscall.SIGSTOP)
	select {
	case <-w:
	case <-x.Done():
	case <-i.Done():
	}
	if len(d) > 0 {
		if err = a.Save(d); err != nil {
			os.Stderr.WriteString("Warning, save failed: " + err.Error() + "!\n")
		}
	}
	a.Close()
	i.Close()
	q()
	close(w)
}
