package diag

import (
	"os"
	"log"
	"log/syslog"
	"io"
)

const (
	LogError = iota
	LogTrace 
	LogDebug

	LogFlagError = 1 << LogError
	LogFlagTrace = 1 << LogTrace
	LogFlagDebug = 1 << LogDebug
	LogFlagSyslog = 0xf0
)

var diag = []*log.Logger{log.New(os.Stderr, "", log.LstdFlags),nil,nil}

func setLogger(idx uint, flags int, prio syslog.Priority) {
	if idx == 0 || (flags & (1 << idx)) != 0 {
		var wrt io.Writer
		wrt = os.Stderr
		logflag := log.LstdFlags
		if flags & LogFlagSyslog == LogFlagSyslog {
			logwrt, e := syslog.New(syslog.LOG_DAEMON|prio, "sargon")
			if e != nil {
				log.Panic("can't create log writer: " + e.Error())
			}
			wrt = logwrt
			logflag = 0
		}
		diag[idx] = log.New(wrt, "", logflag)
	} else {
		diag[idx] = nil
	}
}

func Setup(flags int) {
	setLogger(LogError, flags, syslog.LOG_ERR)
	setLogger(LogTrace, flags, syslog.LOG_INFO)
	setLogger(LogDebug, flags, syslog.LOG_INFO)
}

func Debug(f string, args ...interface{}) {
	if l := diag[LogDebug]; l != nil {
		l.Printf("[DEBUG] " + f, args...)
	}
}

func Trace(f string, args ...interface{}) {
	if l := diag[LogTrace]; l != nil {
		l.Printf("[TRACE] " + f, args...)
	}
}

func Error(f string, args ...interface{}) {
	diag[LogError].Printf(f, args...)
}

