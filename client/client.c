// Author : iamgroot42

#include <stdio.h>
#include <unistd.h>
#include <malloc.h>
#include <string.h>
#include <sys/socket.h>
#include <resolv.h>
#include <netdb.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <arpa/inet.h>

#define CA_PORT 5011 //Port for CA signing/exchange
#define TLS_PORT 5012 //Port for p2p communication
#define RELAY_PORT 5013 //Port for establishing communication with peer
#define BUFFER_SIZE 10000 //Maximum size per message

// Create a socket connection for the given IP and port
int create_socket_and_connect(char* address, int port){
	int sock = 0;
	struct sockaddr_in serv_addr;
	if((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0){
		return 0;
	}
	memset(&serv_addr, '0', sizeof(serv_addr)); 
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_port = htons(port); 
	if(inet_pton(AF_INET, address, &serv_addr.sin_addr)<=0){
		return 0;
	} 
	if(connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0){
		return 0;
	}
	return sock;
}

int OpenListener(int port){
	int sd;
	struct sockaddr_in addr;
	sd = socket(PF_INET, SOCK_STREAM, 0);
	bzero(&addr, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	addr.sin_addr.s_addr = INADDR_ANY;
	if(bind(sd,(struct sockaddr*)&addr,sizeof(addr)) != 0){
		perror("Can't bind port");
		abort();
	}
    if(listen(sd, 10) != 0){
		perror("Can't configure listening port");
		abort();
	}
	return sd;
}

SSL_CTX* InitCTX(void){
	SSL_METHOD *method;
	SSL_CTX *ctx;
	SSL_library_init();
	OpenSSL_add_all_algorithms(); //Load cryptos
	SSL_load_error_strings(); //Bring in and register error messages
	method = TLSv1_2_client_method(); //Create new client-method instance
	ctx = SSL_CTX_new(method); //Create new context
	if(ctx == NULL){
		ERR_print_errors_fp(stderr);
		abort();
	}
	return ctx;
}

SSL_CTX* InitServerCTX(void){
	SSL_METHOD *method;
	SSL_CTX *ctx;
	SSL_library_init();
	OpenSSL_add_all_algorithms(); //Load cryptos
	SSL_load_error_strings(); //Load all error messages
	method = TLSv1_2_server_method(); //Create new server-method instance
	ctx = SSL_CTX_new(method); //Create new context from instance
	if(ctx == NULL){
		ERR_print_errors_fp(stderr);
		abort();
	}
	return ctx;
}

void LoadCertificates(SSL_CTX* ctx, char* CertFile, char* KeyFile){
	// Set the local certificate from CertFile
	if(SSL_CTX_use_certificate_file(ctx, CertFile, SSL_FILETYPE_PEM) <= 0){
		ERR_print_errors_fp(stderr);
		abort();
	}
	// Set the private key from KeyFile (may be the same as CertFile)
	if(SSL_CTX_use_PrivateKey_file(ctx, KeyFile, SSL_FILETYPE_PEM) <= 0){
		ERR_print_errors_fp(stderr);
		abort();
	}
	// Verify private key
	if(!SSL_CTX_check_private_key(ctx)){
		fprintf(stderr, "Private key does not match the public certificate\n");
		abort();
	}
}

void ShowCerts(SSL* ssl){
	X509 *cert;
	char *line;
	cert = SSL_get_peer_certificate(ssl); //Get the server's certificate
	if(cert != NULL){
		printf("Server certificates:\n");
		line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
		printf("Subject: %s\n", line);
		free(line); //Free the malloc'ed string
		line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
		printf("Issuer: %s\n", line);
		free(line); //Free the malloc'ed string
		X509_free(cert); //Free the malloc'ed certificate copy
	}
	else{
		printf("No certificates.\n");
	}
}


// Thread to read incoming data (from server,peer)
void* server_feedback(void* void_listenfd){
	long listenfd = (long)void_listenfd;
	char buffer[BUFFER_SIZE];
	char* STRTOK_SHARED;
	int server, tls_init = 0,ohho = 0;
	memset(buffer,'0',sizeof(buffer));
	printf("woo waiting to read\n");
	while(!tls_init){
		ohho = read(listenfd,buffer,sizeof(buffer));
		buffer[ohho] = 0;
		printf("Ohho relay says %s\n", buffer);
		char *pch = strtok_r(buffer," ", &STRTOK_SHARED);
		if(!strcmp(pch,"/listen")){
			printf("I received a /listen\n");
			tls_init = 1;
			close(listenfd);
		}
	}
	SSL_CTX *ctx;
	//Start listening for incoming TLS connections
	ctx = InitServerCTX(); //Initialize SSL
	// LoadCertificates(ctx, "temp_cert.pem", "temp_key.pem");
	LoadCertificates(ctx, "servercert.pem", "serverkey.pem");
	server = OpenListener(TLS_PORT + 10);
	printf("I am listening ;)\n");
	struct sockaddr_in addr;
	int bytes, len = sizeof(addr);
	SSL *ssl;
	int client = accept(server,  &addr, &len); //Accept connection as usual
	printf("Connection: %s:%d\n",inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));
	ssl = SSL_new(ctx);
	SSL_set_fd(ssl, client);
	SSL_accept(ssl);
	while(1){
		bytes = SSL_read(ssl, buffer, sizeof(buffer));
		if(bytes > 0){
			buffer[bytes] = 0;
			printf(">> %s\n", buffer);
		}
	}
}


int main(int argc, char *argv[]){
	int server, ca, relay, ohho=0, can_message = 0;
	char msg[BUFFER_SIZE];
	char command[100];
	int bytes;
	if(argc < 2){
		printf("Usage: %s <server_ip>\n",argv[0]);
		return 0;
	}
	relay = create_socket_and_connect(argv[1], RELAY_PORT);
	ca = create_socket_and_connect(argv[1], CA_PORT);
	pthread_t pot;
    pthread_create(&pot, NULL, server_feedback, (void*)relay);
    // Generate a CSR, get it signed by CA
	system("yes '' | openssl req -config openssl-server.cnf -newkey rsa:2048 -sha256 -nodes -out servercert.csr -outform PEM  >> /dev/null");
	sleep(2);
	FILE *fp = fopen("./servercert.csr","r");
	char file_content[BUFFER_SIZE];
	strcpy(msg,"/CSR ");
	while(fgets(file_content, BUFFER_SIZE, (FILE*)fp)){
		strcat(msg,file_content);
	}
	fclose(fp);
	write(ca, msg, strlen(msg));
	//Receive certificate
	memset(msg,'0',sizeof(msg));
	ohho = read(ca, msg, sizeof(msg));
	msg[ohho] = 0;
	FILE *fp2 = fopen("./servercert.pem", "w");
	fputs(msg, fp2);
	fclose(fp2);
	close(ca);
    //SSL stuff
    SSL_CTX *ctx;
	SSL *ssl;
	ctx = InitCTX();
	ssl = SSL_new(ctx);
	//SSL stuff
	while(1){
		scanf("%s",command);
		if(!strcmp("/connect",command)){
			char username[100];
			scanf("%s",username);
			strcat(command, " ");
			strcat(command, username);
			write(relay, command, strlen(command));
			can_message = 1;
			// Sleep for 2 seconds (hack,for now)
			sleep(2);
			server = create_socket_and_connect("127.0.0.1", TLS_PORT + 10);
			SSL_set_fd(ssl, server);
			SSL_connect(ssl);
		}
		else if(!strcmp("/identify",command)){
			char username[100];
			scanf("%s",username);
			strcat(command, " ");
			strcat(command, username);
			write(relay, command, strlen(command));
		}
		else if(!strcmp("/exit",command)){
			// pthread_kill(pot,0);
			close(relay);

			SSL_CTX_free(ctx); //Release context
			close(server);

			printf(">> Exiting!\nThanks for using IRsea!\n");
			return 0;
		}
		else if(!strcmp("/msg",command)){
			if(!can_message){
				printf(">> Connect before you can start talking!\n");
			}
			else{
				fgets(msg, BUFFER_SIZE, stdin);
				SSL_write(ssl, msg, strlen(msg)); //Encrypt and send message
			}
		}
		else if(!strcmp("/who",command)){
			write(relay, command, strlen(command));
		}
		else{
			printf(">> Invalid command! Please read the README for the list of supported commands\n");
		}
	}
}
