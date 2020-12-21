default: all
all: CAserver

CAserver: CAserver.cpp
	mkdir -p tmp
	g++ -o CAserver -std=c++14 CAserver.cpp -lssl -lcrypto

clean:
	rm CAserver