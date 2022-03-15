package utils

const (
	ProcessEntrySize = 568 // Used by getProc(). Result of: unsafe.Sizeof(windows.ProcessEntry32{}
	ModuleEntrySize  = 1080
)
