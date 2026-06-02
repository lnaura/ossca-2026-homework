package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -no-strip -target bpfel Xdp bpf/xdp.c

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
)

type ifreqIndex struct {
	Name  [unix.IFNAMSIZ]byte
	Index int32
	_     [20]byte
}

func ifaceIndex(name string) (int, error) {
	if len(name) >= unix.IFNAMSIZ {
		return 0, fmt.Errorf("interface name too long")
	}

	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return 0, fmt.Errorf("socket: %w", err)
	}
	defer unix.Close(fd)

	var ifr ifreqIndex
	copy(ifr.Name[:], name)

	_, _, errno := unix.Syscall(
		unix.SYS_IOCTL,
		uintptr(fd),
		unix.SIOCGIFINDEX,
		uintptr(unsafe.Pointer(&ifr)),
	)
	if errno != 0 {
		return 0, fmt.Errorf("ioctl SIOCGIFINDEX %s: %w", name, errno)
	}
	return int(ifr.Index), nil
}

func clearBPFMap(m *ebpf.Map) error {
	var key, val uint32
	var keys []uint32

	iter := m.Iterate()
	for iter.Next(&key, &val) {
		keys = append(keys, key)
	}
	if err := iter.Err(); err != nil {
		return err
	}
	for _, k := range keys {
		if err := m.Delete(k); err != nil {
			return err
		}
	}
	return nil
}

type ifState struct {
	objs XdpObjects
	lnk  link.Link
}

var (
	mu     sync.Mutex
	ifaces = make(map[string]*ifState)
)

type attachReq struct {
	Ifname string `json:"ifname"`
}
type attachResp struct {
	Ifname   string `json:"ifname"`
	Hook     string `json:"hook"`
	Attached bool   `json:"attached"`
}

type blockReq struct {
	IP string `json:"ip"`
}
type blockResp struct {
	Ifname    string `json:"ifname"`
	BlockedIP string `json:"blocked_ip"`
}

type clearResp struct {
	Ifname  string `json:"ifname"`
	Cleared bool   `json:"cleared"`
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	http.Error(w, msg, status)
}

func handleAttach(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	var req attachReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.Ifname == "" {
		writeErr(w, http.StatusBadRequest, "ifname is required")
		return
	}

	idx, err := ifaceIndex(req.Ifname)
	if err != nil {
		writeErr(w, http.StatusBadRequest, fmt.Sprintf("interface not found: %v", err))
		return
	}

	mu.Lock()
	defer mu.Unlock()

	if _, ok := ifaces[req.Ifname]; ok {
		writeJSON(w, http.StatusOK, attachResp{Ifname: req.Ifname, Hook: "xdp", Attached: true})
		return
	}

	objs := XdpObjects{}
	if err := LoadXdpObjects(&objs, nil); err != nil {
		writeErr(w, http.StatusInternalServerError, fmt.Sprintf("load eBPF objects: %v", err))
		return
	}

	lnk, err := link.AttachXDP(link.XDPOptions{
		Interface: idx,
		Program:   objs.XdpFilter,
		Flags:     link.XDPGenericMode,
	})
	if err != nil {
		objs.Close()
		writeErr(w, http.StatusInternalServerError, fmt.Sprintf("attach XDP: %v", err))
		return
	}

	ifaces[req.Ifname] = &ifState{objs: objs, lnk: lnk}

	writeJSON(w, http.StatusOK, attachResp{Ifname: req.Ifname, Hook: "xdp", Attached: true})
}

func handleBlock(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	ifname := strings.TrimPrefix(r.URL.Path, "/bpf/block/")
	if ifname == "" {
		writeErr(w, http.StatusBadRequest, "ifname required in path")
		return
	}

	var req blockReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}

	parsed := net.ParseIP(req.IP)
	if parsed == nil {
		writeErr(w, http.StatusBadRequest, "invalid IP address")
		return
	}
	ip4 := parsed.To4()
	if ip4 == nil {
		writeErr(w, http.StatusBadRequest, "only IPv4 addresses are supported")
		return
	}

	mu.Lock()
	defer mu.Unlock()

	state, ok := ifaces[ifname]
	if !ok {
		writeErr(w, http.StatusBadRequest, fmt.Sprintf("interface %s is not attached", ifname))
		return
	}

	key := uint32(ip4[3])<<24 | uint32(ip4[2])<<16 | uint32(ip4[1])<<8 | uint32(ip4[0])
	val := uint32(1)

	if err := state.objs.BlockedIps.Put(key, val); err != nil {
		writeErr(w, http.StatusInternalServerError, fmt.Sprintf("update BPF map: %v", err))
		return
	}

	writeJSON(w, http.StatusOK, blockResp{Ifname: ifname, BlockedIP: req.IP})
}

func handleClear(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	ifname := strings.TrimPrefix(r.URL.Path, "/bpf/clear/")
	if ifname == "" {
		writeErr(w, http.StatusBadRequest, "ifname required in path")
		return
	}

	mu.Lock()
	defer mu.Unlock()

	state, ok := ifaces[ifname]
	if !ok {
		writeErr(w, http.StatusBadRequest, fmt.Sprintf("interface %s is not attached", ifname))
		return
	}

	if err := clearBPFMap(state.objs.BlockedIps); err != nil {
		writeErr(w, http.StatusInternalServerError, fmt.Sprintf("clear BPF map: %v", err))
		return
	}

	writeJSON(w, http.StatusOK, clearResp{Ifname: ifname, Cleared: true})
}

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/bpf/attach", handleAttach)
	mux.HandleFunc("/bpf/block/", handleBlock)
	mux.HandleFunc("/bpf/clear/", handleClear)

	log.Println("listening on :8080")
	log.Fatal(http.ListenAndServe(":8080", mux))
}
