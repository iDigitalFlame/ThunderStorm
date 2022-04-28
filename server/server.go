package server

import (
	"context"
	"flag"
	"net/http"
	"os"
	"syscall"

	"github.com/PurpleSec/logx"
	"github.com/iDigitalFlame/ThunderStorm/cirrus"
	"github.com/iDigitalFlame/xmt/c2"
	"github.com/iDigitalFlame/xmt/com/limits"
)

const usage = `Cirrus C2/Rest Engine
Part of the ThunderStorm Project (https://dij.sh/ts)
(c) 2019 - 2022 iDigitalFlame

Usage: cirrus -b <bind_address:port> [-p password] [-no-auth] [-l log_file] [-n log_level] [-c csv_output] [-t tracker]

Required Arguments:
  -b <bind_address:port>        Specify a "address:port" that the ReST API will
                                 be bound to.

Optional Arguments:
  -p <password>                 Specify a password to be used in the "X-CirrusAuth"
                                 HTTP header for connections. If this is empty, the
                                 "-no-auth" argument must be specified to force no
                                 password authentication.
  -no-auth                      Argument that can be used to force Cirrus to NOT
                                 validate connections with a password. If a password
                                 is specified with "-p", this argument is ignored.
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

// CmdLine will attempt to build and run a Cirrus instance. This function
// will block until completion.
func CmdLine() {
	var (
		p, a, l, c, t string
		n             bool
		e             int
		err           error
		f             = flag.NewFlagSet("Cirrus C2/Rest Engine - ThunderStorm", flag.ContinueOnError)
	)
	f.Usage = func() {
		os.Stdout.WriteString(usage)
		os.Exit(2)
	}
	f.StringVar(&p, "p", "", "")
	f.StringVar(&a, "b", "", "")
	f.StringVar(&l, "l", "", "")
	f.StringVar(&c, "c", "", "")
	f.StringVar(&t, "t", "", "")
	f.BoolVar(&n, "no-auth", false, "")
	f.IntVar(&e, "n", int(logx.Info), "")

	switch err = f.Parse(os.Args[1:]); err {
	case nil:
	case flag.ErrHelp:
		f.Usage()
	default:
		errExit(err)
	}

	if len(a) == 0 {
		f.Usage()
	}

	var log logx.Log
	if len(l) > 0 {
		if log, err = logx.File(l, logx.Normal(e, logx.Info), logx.Append); err != nil {
			errExit(err)
		}
	} else {
		log = logx.Console(logx.Normal(e, logx.Info))
	}

	if len(p) == 0 && !n {
		os.Stderr.WriteString(`Argument "-no-auth" must be specified if no password is specified!` + "\n")
		os.Exit(1)
	}

	var (
		x, q = context.WithCancel(context.Background())
		srv  = c2.NewServerContext(x, log)
		api  = cirrus.NewContext(x, srv, p)
	)
	if err = api.TrackStats(c, t); err != nil {
		api.Close()
		srv.Close()
		errExit(err)
	}

	go func() {
		if err := api.Listen(a); err != http.ErrServerClosed {
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
	case <-srv.Done():
	}
	api.Close()
	srv.Close()
	q()
	close(w)
}
func errExit(e error) {
	os.Stderr.WriteString("Error " + e.Error() + "!\n")
	os.Exit(1)
}
