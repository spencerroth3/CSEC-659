package utils

import "syscall"

type Inject struct {
	Pid              uint32
	DllPath          string
	DllName          string
	DLLSize          uint32
	Privilege        string
	RemoteProcHandle uintptr
	RemoteFuncHandle uintptr
	RemoteFuncName   string
	Lpaddr           uintptr
	LoadLibAddr      uintptr
	RThread          uintptr
	Token            syscall.Token
}
