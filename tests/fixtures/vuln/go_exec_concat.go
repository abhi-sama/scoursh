package main

import (
	"net/http"
	"os/exec"
)

// handler builds a shell command by concatenating request-derived input
// directly into the command string - true positive for
// SAST-GO-EXEC_CONCAT-01.
func handler(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("dir")
	cmd := exec.Command("sh", "-c", "ls -la "+target)
	out, _ := cmd.Output()
	w.Write(out)
}
