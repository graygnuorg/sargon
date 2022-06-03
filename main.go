package main

import (
	"os"
	"github.com/docker/go-plugins-helpers/authorization"
	"github.com/sevlyar/go-daemon"
	"github.com/pborman/getopt/v2"
	"fmt"
	"os/signal"
	"path/filepath"
	"syscall"
	"sargon/diag"
	"sargon/server"
)

func main() {
	config_file := "/etc/docker/sargon.json"
        foreground := false
	debug_mode := false
	trace_mode := false
	help_mode := false
	diag_flags := 0

	optset := getopt.New()
	optset.SetProgram(filepath.Base(os.Args[0]))
	optset.SetParameters("")
	optset.FlagLong(&foreground, "foreground", 'f', "remain in foreground")
	optset.FlagLong(&debug_mode, "debug", 'd', "verbose debugging")
	optset.FlagLong(&trace_mode, "trace", 't', "enable trace output")
	optset.FlagLong(&config_file, "config", 'c', "read this configuration file")
	optset.FlagLong(&help_mode, "help", 'h', "display this help summary")

	if err := optset.Getopt(os.Args, nil); err != nil {
		fmt.Fprintln(os.Stderr, err)
		optset.PrintUsage(os.Stderr)
		os.Exit(1)
	}

	if help_mode {
		optset.PrintUsage(os.Stdout)
		os.Exit(0)
	}

	if debug_mode {
		diag_flags |= diag.LogFlagDebug
	}
	if trace_mode {
		diag_flags |= diag.LogFlagTrace
	}
	
	sargon := &server.Sargon{
		Pidfile: "/var/run/sargon.pid",
		LdapConf: "/etc/ldap.conf:/etc/ldap/ldap.conf:/etc/openldap/ldap.conf",
		AnonymousUser: "ANONYMOUS",
	}
	sargon.ReadConfig(config_file)

	if !foreground {
		diag_flags |= diag.LogFlagSyslog
	}
	diag.Setup(diag_flags)

	if !foreground {
		ctx := &daemon.Context{
			PidFileName: sargon.Pidfile,
			PidFilePerm: 0644,
			WorkDir: "/",
			Umask: 027,
			}

		d, err := ctx.Reborn()
		if err != nil {
			diag.Error("can't go daemon: ", err)
		}
		if d != nil {
			return
		}
		defer ctx.Release()
	}
	diag.Trace("start up")

	signal_chan := make(chan os.Signal, 1)
	signal.Notify(signal_chan,
		      syscall.SIGINT,
		      syscall.SIGTERM,
		      syscall.SIGQUIT)
	
	go worker(sargon)
	
	_ = <-signal_chan
	os.Remove(sargon.Pidfile)
	diag.Trace("normal shutdown")
	os.Exit(0)
} 

func worker(srg *server.Sargon) {
	h := authorization.NewHandler(srg)
	if err := h.ServeUnix("sargon", 0); err != nil {
		diag.Error(err.Error())
		os.Exit(1)
	}
}
