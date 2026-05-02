package main

import (
	"encoding/json"
	"net/http"
	"os"
	"os/exec"
	"syscall"
)

type Req struct {
	Path string   `json:"path"`
	Args []string `json:"args"`
}

func handler(w http.ResponseWriter, r *http.Request) {
	var req Req
	json.NewDecoder(r.Body).Decode(&req)

	cmd := exec.Command(req.Path, req.Args...)

	cmd.SysProcAttr = &syscall.SysProcAttr{
		Unshareflags: syscall.CLONE_NEWNET,
	}

	cmd.Start()

	pid := cmd.Process.Pid

	go cmd.Wait()

	res := map[string]int{
		"parent_pid": os.Getpid(),
		"child_pid":  pid,
	}

	json.NewEncoder(w).Encode(res)
}

func main() {
	http.HandleFunc("/unshare/netns", handler)
	http.ListenAndServe(":8080", nil)
}
