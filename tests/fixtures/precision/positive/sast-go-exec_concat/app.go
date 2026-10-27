package main
func f(input string) { exec.Command("sh", "-c", "echo " + input).Run() }
