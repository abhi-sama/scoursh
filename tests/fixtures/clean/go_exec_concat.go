package main

import (
	"net/http"
	"os/exec"
)

// handler passes the request-derived argument as its own exec.Command
// element, never concatenated into a shell string - safe equivalent for
// SAST-GO-EXEC_CONCAT-01.
func handler(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("dir")
	cmd := exec.Command("ls", "-la", target)
	out, _ := cmd.Output()
	w.Write(out)
}
