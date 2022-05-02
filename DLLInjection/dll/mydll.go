package main

import "C"
import (
	"fmt"

	wapi "github.com/iamacarpet/go-win64api"
)

//export CreateUser
func CreateUser() {
	username := "mclovin"
	fullname := "The McLovin"
	password := "ThisIsMyPass123!"

	ok, _ := wapi.UserAdd(username, fullname, password)
	fmt.Print(ok)
}

func main() {
	// Need a main function to make CGO compile package as C shared library
}
