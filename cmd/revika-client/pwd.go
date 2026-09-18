package main

import "fmt"

// runPWD always reports the namespace root: there is no cd command to change it.
func runPWD() error {
	fmt.Println("rvk:/")
	return nil
}
