default: all
all: server
	./create-folders.sh

server: server.cpp
	g++ -o server -g -std=c++14 server.cpp -lssl -lcrypto

clean:
	rm server
	rm -rf messages certs tmp
