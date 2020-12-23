default: all
all: CAserver

CAserver: CAserver.cpp
	mkdir -p tmp
	g++ -o CAserver -std=c++14 CAserver.cpp -lssl -lcrypto
	sudo ./password_permissions.sh

clean:
	rm CAserver