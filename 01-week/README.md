# 01주차 과제

## 학습내용
* linux process와 kernel의 task_struct
* linux namespace와 kernel의 nxproxy, cred
* filesystem isolation과 fs_struct
* namespace 분리를 위한 clone, unshare, setns system call
* filesystem 격리를 위한 pivot_root

## 목표
linux의 network namespace가 프로세스 단위로 분리될 수 있음을 이해하고, `unshare(CLONE_NEWNET)`을 사용해 자식 프로세스를 별도의 Network Namespace에서 실행한다. \
이번 과제는 Network Namespace 생성 여부만 검증한다.

다음은 구현하지 않는다.
- veth 생성
- IP 할당
- route 설정

## 구현 요구사항
1. 서버는 `/unshare/netns` URL path를 제공해야 한다. (8080 port로 listen 한다)
2. `/unshare/netns`는 POST 요청을 받는다.
3. Request body는 JSON 형식이며 다음 필드를 가진다.
	```json
	{
		"path": "/bin/sleep",
     	"args": ["30"]
	}
	```
   - path는 실행 파일의 절대 경로여야 한다.
   - args는 실행 파일에 전달할 인자 목록이다.
   - shell command string 형태는 허용하지 않는다.

4. `/unshare/netns`는 요청을 받으면 자식 프로세스를 생성해야 한다.
5. 자식 프로세스는 새로운 network namespace 안에서 실행되어야 한다.
6. network namespace 분리는 반드시 자식 프로세스에만 적용되어야 한다.
   부모 HTTP API 서버의 network namespace는 변경되면 안 된다.
7. 자식 프로세스는 request body로 전달된 path를 exec해야 한다.
8. API response는 JSON 형식으로 다음 값을 반환해야 한다.
	```json
   	{
    	"parent_pid": 12345,
     	"child_pid": 12346	
   	}
9.  parent_pid는 HTTP API server process의 PID여야 한다.
10. child_pid는 새 network namespace에서 path를 실행 중인 process의 PID여야 한다.
11. 자식 프로세스가 종료된 후 zombie process가 남지 않도록 부모 프로세스는 wait 처리를 해야 한다.
12. 본 과제는 root 권한 또는 network namespace 생성 권한이 있는 Linux 환경에서 실행한다고 가정한다.
