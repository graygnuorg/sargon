package main

import (
	"flag"
	"os"
	"github.com/docker/go-plugins-helpers/authorization"
	"github.com/sevlyar/go-daemon"
	"log"
	"log/syslog"
	"os/signal"
	"syscall"
)

var (
	debug_mode bool
	trace_mode bool
)

func debug(f string, args ...interface{}) {
	if (debug_mode) {
		log.Printf("[DEBUG] " + f, args...)
	}
}

func trace(f string, args ...interface{}) {
	if (trace_mode || debug_mode) {
		log.Printf("[TRACE] " + f, args...)
	}
}

func main() {
	var config_file string;
	var foreground bool;

	flag.BoolVar(&foreground, "foreground", false,
		"remain in foreground")
	flag.BoolVar(&debug_mode, "debug", false,
		"verbose debugging")
	flag.BoolVar(&trace_mode, "trace", false,
		"verbose debugging")

	flag.StringVar(&config_file, "config", "/etc/docker/sargon.json",
	                "Sargon configuration file")
	flag.Parse()

	sargon := &Sargon{
		Pidfile: "/var/run/sargon.pid",
		LdapConf: "/etc/ldap.conf:/etc/ldap/ldap.conf:/etc/openldap/ldap.conf",
		AnonymousUser: "ANONYMOUS",
	}
	sargon.ReadConfig(config_file)

	if !foreground {
		logwrt, e := syslog.New(syslog.LOG_DAEMON|syslog.LOG_NOTICE,
				        "sargon")
		if e != nil {
			log.Panic("can't create log writer: " + e.Error())
		}
		log.SetOutput(logwrt)
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
	log.Println("start up")

	signal_chan := make(chan os.Signal, 1)
	signal.Notify(signal_chan,
		      syscall.SIGINT,
		      syscall.SIGTERM,
		      syscall.SIGQUIT)
	
	go worker(sargon)
	
	_ = <-signal_chan
	os.Remove(sargon.Pidfile)
	log.Println("normal shutdown")
	os.Exit(0)
} 

func worker(srg *Sargon) {
	h := authorization.NewHandler(srg)
	if err := h.ServeUnix("sargon", 0); err != nil {
		log.Panic(err.Error())
	}
}
