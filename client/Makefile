# iamgroot42

all: client.cpp
	g++ -std=c++11 client.cpp -o client -pthread -lssl -lcrypto -lmcrypt
	@echo Compiled!

clean:
	@-$(RM) client
	@echo Cleaned!
