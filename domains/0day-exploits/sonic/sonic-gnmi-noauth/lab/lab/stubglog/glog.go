package glog

import "log"

type Level int32
type Verbose bool

func V(level Level) Verbose { return true }

func (v Verbose) Info(args ...interface{}) {
	if v {
		log.Print(args...)
	}
}

func (v Verbose) Infof(format string, args ...interface{}) {
	if v {
		log.Printf(format, args...)
	}
}

func Info(args ...interface{}) { log.Print(args...) }

func Infof(format string, args ...interface{}) { log.Printf(format, args...) }

func Warning(args ...interface{}) { log.Print(args...) }

func Errorf(format string, args ...interface{}) { log.Printf(format, args...) }
