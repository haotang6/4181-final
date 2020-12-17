server: server.cpp
	g++ -o server -std=c++14 server.cpp -lssl -lcrypto
client: client.cpp
	g++ -o client -std=c++14 client.cpp -lssl -lcrypto
server-cred:
	./server-credentials.sh
