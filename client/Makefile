# iamgroot42

all: client.c
	gcc -pthread client.c -o client -pthread -lssl -lcrypto
	@echo Compiled!

clean:
	@-$(RM) client
	@echo Cleaned!
