default: all
all: CAserver

CAserver: CAserver.cpp
	mkdir -p tmp
	g++ -o CAserver -std=c++14 CAserver.cpp -lssl -lcrypto
	cp initial_users.txt user_passwords.txt
	rm initial_users.txt
	sudo ./password_permissions.sh

clean:
	rm CAserver