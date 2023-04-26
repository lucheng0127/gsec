build_dir=build

all: dir cover gbin

dir: dir_build dir_cover

dir_build:
	mkdir -p build

dir_cover:
	mkdir -p cover

cover: dir_cover ut

ut:
	go test -gcflags=-l -coverprofile cover/cover.out ./agent/pkg/...
	go tool cover -html=./cover/cover.out -o cover/cover.html

gbin: gapi gagent

gapi:
	go build -o build/gsec api/gsec.go

gagent:
	go build -o build/gsecagent agent/gsecagent.go

clean:
	rm -rf ${build_dir}/*
	rm -rf cover