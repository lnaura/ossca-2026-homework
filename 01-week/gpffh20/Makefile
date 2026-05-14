APP=app
GO=go

.PHONY: build run clean

build:
	$(GO) build -o $(APP) .

run: build
	sudo ./$(APP)

clean:
	rm -f $(APP)
