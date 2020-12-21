default: all
all: client getcert changepw recvmsg sendmsg

client: client.cpp
	g++ -o client -std=c++14 client.cpp -lssl -lcrypto
getcert: getcert.cpp client_helper.hpp
	g++ -o getcert -std=c++14 getcert.cpp client_helper.hpp -lssl -lcrypto
changepw: changepw.cpp client_helper.hpp
	g++ -o changepw -std=c++14 changepw.cpp client_helper.hpp -lssl -lcrypto
recvmsg: recvmsg.cpp client_helper.hpp
	g++ -o recvmsg -std=c++14 recvmsg.cpp client_helper.hpp -lssl -lcrypto
sendmsg: sendmsg.cpp client_helper.hpp
	g++ -o sendmsg -std=c++14 sendmsg.cpp client_helper.hpp -lssl -lcrypto
clean:
	rm client getcert changepw recvmsg sendmsg