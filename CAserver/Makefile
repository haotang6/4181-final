all: CAserver

server: CAserver.cpp
	g++ -o CAserver -std=c++14 CAserver.cpp -lssl -lcrypto

clean:
	rm CAserver