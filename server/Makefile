all: server

server: server.cpp
	g++ -o server -std=c++14 server.cpp -lssl -lcrypto

clean:
	rm server