package main

import "runtime"

func runtimeVersionImpl() string { return runtime.Version() }
