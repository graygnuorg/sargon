package main

import (
	"fmt"
	"flag"
	"encoding/json"
	"io/ioutil"
	"os"
	"strings"
	"github.com/docker/go-plugins-helpers/authorization"
	"github.com/sevlyar/go-daemon"
	"log"
	"log/syslog"
	"os/signal"
	"syscall"
)

type Config struct {
	Pidfile   string `json:"pidfile"`
	Mount     []string `json:"mount"`
	AllowPriv bool `json:"allowpriv"`
}

func readConfig(f string) Config {
	raw, err := ioutil.ReadFile(f)
	if err != nil {
		fmt.Println(err.Error())
		os.Exit(1)
	}
	c := Config{ Pidfile: "/var/run/sargon.pid",
		     AllowPriv: false }
	json.Unmarshal(raw, &c)
	return c;
}

var (
	config Config
)

func main() {
	var config_file string;
	var foreground bool;

	flag.BoolVar(&foreground, "foreground", false,
			"remain in foreground")
	flag.StringVar(&config_file, "config", "/etc/docker/sargon.json",
	                "Sargon configuration file")
	flag.Parse()

	config = readConfig(config_file)
	for i, x := range config.Mount {
		if !strings.HasSuffix(x, "/") {
			config.Mount[i] = x + "/"
		}
	}
	if (len(config.Mount) == 0) {
		log.Println("warning: no mount points configured")
	}

	if !foreground {
		logwrt, e := syslog.New(syslog.LOG_DAEMON|syslog.LOG_NOTICE,
				        "sargon")
		if e != nil {
			log.Panic("can't create log writer: " + e.Error())
		}
		log.SetOutput(logwrt)
		ctx := &daemon.Context{
			PidFileName: config.Pidfile,
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
	
	go worker()
	
	_ = <-signal_chan
	os.Remove(config.Pidfile)
	log.Println("normal shutdown")
	os.Exit(0)
}

func worker() {
	sargon, err := newPlugin()
	if err != nil {
		log.Panic(err.Error())
	}

	h := authorization.NewHandler(sargon)
	if err := h.ServeUnix("sargon", 0); err != nil {
		log.Panic(err.Error())
	}
}
