default: all
all: getcert changepw recvmsg sendmsg

getcert: getcert.cpp client_helper.hpp
	g++ -o getcert -g -std=c++14 getcert.cpp client_helper.hpp -lssl -lcrypto
changepw: changepw.cpp client_helper.hpp
	g++ -o changepw -g -std=c++14 changepw.cpp client_helper.hpp -lssl -lcrypto
recvmsg: recvmsg.cpp client_helper.hpp
	g++ -o recvmsg -g -std=c++14 recvmsg.cpp client_helper.hpp -lssl -lcrypto
sendmsg: sendmsg.cpp client_helper.hpp
	g++ -o sendmsg -g -std=c++14 sendmsg.cpp client_helper.hpp -lssl -lcrypto
clean:
	rm getcert changepw recvmsg sendmsg

install:getcert changepw recvmsg sendmsg
	rm -rf ../client-$(USER)
	mkdir ../client-$(USER)
	mkdir ../client-$(USER)/client_files
	mkdir ../client-$(USER)/tmp
	cp getcert ../client-$(USER)
	cp changepw ../client-$(USER)
	cp recvmsg ../client-$(USER)
	cp sendmsg ../client-$(USER)
	cp ca-chain.cert.pem ../client-$(USER)
	cp cgencsr.sh ../client-$(USER)
	cp test.txt ../client-$(USER)
	cp config ../client-$(USER)
	cp openssl.cnf ../client-$(USER)

	