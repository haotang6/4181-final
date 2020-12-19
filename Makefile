all: server client getcert

server: server.cpp
	g++ -o server -std=c++14 server.cpp -lssl -lcrypto
client: client.cpp
	g++ -o client -std=c++14 client.cpp -lssl -lcrypto
server-cred:
	./server-credentials.sh
getcert: getcert.cpp client_helper.hpp
	g++ -o getcert -std=c++14 getcert.cpp client_helper.hpp -lssl -lcrypto
changepw: changepw.cpp client_helper.hpp
	g++ -o changepw -std=c++14 changepw.cpp client_helper.hpp -lssl -lcrypto


clean:
	rm server client