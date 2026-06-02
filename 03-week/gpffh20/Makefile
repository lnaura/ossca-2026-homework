.PHONY: build clean run

build:
	go generate ./...
	go build -o app .

clean:
	rm -f app xdp_bpfel*.go xdp_bpfel*.o

run: build
	sudo ./app