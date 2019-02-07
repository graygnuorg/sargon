package main

import (
	"flag"
	"os"
	"github.com/docker/go-plugins-helpers/authorization"
	"github.com/sevlyar/go-daemon"
	"log"
	"os/signal"
	"syscall"
	"sargon/diag"
	"sargon/server"
)

func main() {
	var (
		config_file string
	        foreground bool
		debug_mode bool
		trace_mode bool
		diag_flags int
	)
	
	flag.BoolVar(&foreground, "foreground", false,
		"remain in foreground")
	flag.BoolVar(&debug_mode, "debug", false,
		"verbose debugging")
	flag.BoolVar(&trace_mode, "trace", false,
		"verbose debugging")

	flag.StringVar(&config_file, "config", "/etc/docker/sargon.json",
	                "Sargon configuration file")
	flag.Parse()

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
			log.Fatal("can't go daemon: ", err)
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
