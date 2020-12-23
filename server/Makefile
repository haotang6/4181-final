default: all
all: server
	rm -r messages certs tmp
	./create-folders.sh

server: server.cpp
	g++ -o server -g -std=c++14 server.cpp -lssl -lcrypto

clean:
	rm server
