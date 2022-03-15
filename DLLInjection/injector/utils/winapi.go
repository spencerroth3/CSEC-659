package utils

import (
	"syscall"
)

// Create instances of WinAPI functions
var (
	kernel32dll = syscall.NewLazyDLL("kernel32.dll")

	openProcess    = kernel32dll.NewProc("OpenProcess")
	getProcAddress = kernel32dll.NewProc("GetProcAddress")
	virtualAllocEx = kernel32dll.NewProc("VirtualAllocEx")
	//virtualProtectEx    = kernel32dll.NewProc("VirtualProtectEx")
	virtualFreeEx       = kernel32dll.NewProc("VirtualFreeEx")
	writeProcessMemory  = kernel32dll.NewProc("WriteProcessMemory")
	createRemoteThread  = kernel32dll.NewProc("CreateRemoteThread")
	waitForSingleObject = kernel32dll.NewProc("WaitForSingleObject")
	closeHandle         = kernel32dll.NewProc("CloseHandle")
	getExitCodeThread   = kernel32dll.NewProc("GetExitCodeThread")
	loadLibraryA        = kernel32dll.NewProc("LoadLibraryA")
	getModuleHandleA    = kernel32dll.NewProc("GetModuleHandleA")
)
