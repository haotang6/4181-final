default: all
all: server

server: server.cpp
	mkdir -p user_certificates
	g++ -o server -std=c++14 server.cpp -lssl -lcrypto

clean:
	rm server