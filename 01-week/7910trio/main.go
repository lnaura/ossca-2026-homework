package main

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
	"os/exec"
	"syscall"
)

// /unshare/netns 엔드포인트에 대한 요청 본문 구조체
type RequestBody struct {
	Path string   `json:"path"`
	Args []string `json:"args"`
}

// /unshare/netns 엔드포인트에 대한 응답 본문 구조체
type ResponseBody struct {
	ParentPID int `json:"parent_pid"`
	ChildPID  int `json:"child_pid"`
}

func handleUnshareNetns(w http.ResponseWriter, r *http.Request) {

	// Post 요청만 허용
	if r.Method != http.MethodPost {
		http.Error(w, "Only POST requests are allowed", http.StatusMethodNotAllowed)
		return
	}

	var reqBody RequestBody

	// 요청 본문(r.Body)을 JSON으로 디코딩
	if err := json.NewDecoder(r.Body).Decode(&reqBody); err != nil {
		http.Error(w, "Invalid JSON in request body", http.StatusBadRequest)
		return
	}

	// 절대 경로 검증
	if reqBody.Path == "" || reqBody.Path[0] != '/' {
		http.Error(w, "Path must be an absolute path", http.StatusBadRequest)
		return
	}

	// 실행할 명령 준비
	// ex: exec.Command("/bin/bash", "30") -> /bin/bash 30 실행
	cmd := exec.Command(reqBody.Path, reqBody.Args...)

	// 자식 프로세스를 새 네트워크 네임스페이스에서 실행
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Unshareflags: syscall.CLONE_NEWNET,
	}

	// 자식 프로세스 시작
	// 1. child가 생성(clone)되고,
	// 2. exec 전 unshare(CLONE_NEWNET) 호출됨
	// 3. child가 새 Network Namespace에 들어감
	// 4. execve(path, args)로 대상 프로그램 실행
	if err := cmd.Start(); err != nil {
		http.Error(w, "Failed to start child process: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// 응답 생성
	respBody := ResponseBody{
		ParentPID: os.Getpid(),
		ChildPID:  cmd.Process.Pid,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(respBody)

	// 응답 후 별도 goroutine에서 wait 처리
	// -> zombie 프로세스 방지
	// () -> 즉시 실행되는 익명 함수
	go func() {
		err := cmd.Wait()
		if err != nil {
			log.Printf("Error waiting for child process: %v", err)
		}
	}()
}

func main() {
	http.HandleFunc("/unshare/netns", handleUnshareNetns)

	log.Println("Server is running on http://localhost:8080")
	if err := http.ListenAndServe(":8080", nil); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}
