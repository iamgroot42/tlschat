// #include <bits/stdc++.h>
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
#define TLS_PORT 5012 //Port for CA signing/exchange
#define BUFFER_SIZE 10000 //Maximum size per message

// Create a socket connection for the given IP and port
int create_socket_and_connect(char* address, int port){
	int sock = 0;
	struct sockaddr_in serv_addr;
	if((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0){
		// cerr<<">> Socket creation error"<<endl;
		return 0;
	}
	memset(&serv_addr, '0', sizeof(serv_addr)); 
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_port = htons(port); 
	if(inet_pton(AF_INET, address, &serv_addr.sin_addr)<=0){
		// cerr<<">> Invalid address"<<endl;
		return 0;
	} 
	if( connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0){
		// cerr<<">> Connection Failed"<<endl;
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
	if ( bind(sd,(struct sockaddr*)&addr,sizeof(addr)) != 0 ){
		perror("can't bind port");
		abort();
	}
    if ( listen(sd, 10) != 0 ){
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
		free(line); //Dree the malloc'ed string
		line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
		printf("Issuer: %s\n", line);
		free(line); //Free the malloc'ed string
		X509_free(cert); //Free the malloc'ed certificate copy
	}
	else{
		printf("No certificates.\n");
	}
}


void Servlet(SSL* ssl){
	char buf[BUFFER_SIZE];
	char reply[BUFFER_SIZE];
	int sd, bytes;
	const char* HTMLecho="<html><body><pre>%s</pre></body></html>\n\n";

	if(SSL_accept(ssl) == -1){	/* do SSL-protocol accept */
		ERR_print_errors_fp(stderr);
	}
	else{
		ShowCerts(ssl);	/* get any certificates */
		bytes = SSL_read(ssl, buf, sizeof(buf)); /* get request */
		if(bytes > 0){
			buf[bytes] = 0;
			printf("Client msg: \"%s\"\n", buf);
			sprintf(reply, HTMLecho, buf); /* construct reply */
			SSL_write(ssl, reply, strlen(reply)); /* send reply */
		}
		else{
			ERR_print_errors_fp(stderr);
			}
	}
	sd = SSL_get_fd(ssl); /* get socket connection */
	SSL_free(ssl); /* release SSL state */
	close(sd); /* close connection */
}

int main(int argc, char *argv[]){
	SSL_CTX *ctx;
	int server;
	SSL *ssl;
	char buf[BUFFER_SIZE];
	int bytes;
	if(argc<2){
		printf("Usage: %s <server_ip>\n",argv[0]);
		return 0;
	}
	int mode;
	printf("Enter mode (0:server, 1:client)\n");
	scanf("%d",&mode);
	// Client mode:
	if(mode){
		ctx = InitCTX();
		server = create_socket_and_connect(argv[1], TLS_PORT);
		ssl = SSL_new(ctx); //Create new SSl connection state
		SSL_set_fd(ssl, server); //Attach socket descriptor
		if( SSL_connect(ssl) == -1 ){
			ERR_print_errors_fp(stderr);
		}
		else{
			char *msg = "Hello???";
			printf("Connected with %s encryption\n", SSL_get_cipher(ssl));
			ShowCerts(ssl); //Get any certificates
			SSL_write(ssl, msg, strlen(msg)); //Encrypt and send message
			bytes = SSL_read(ssl, buf, sizeof(buf)); //Get reply and decrypt
			buf[bytes] = 0;
			printf("Received: \"%s\"\n", buf);
			SSL_free(ssl); //Release connection state
		}
		close(server); //Close socket
		SSL_CTX_free(ctx); //Release context
	}
	else{
		ctx = InitServerCTX(); //Initialize SSL
		LoadCertificates(ctx, "temp_cert.pem", "temp_key.pem");
		server = OpenListener(TLS_PORT);
		while(1){
			struct sockaddr_in addr;
        	int len = sizeof(addr);
			SSL *ssl;
			int client = accept(server,  &addr, &len); //Accept connection as usual
			printf("Connection: %s:%d\n",
			inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));
			ssl = SSL_new(ctx); //Get new SSL state with context
			SSL_set_fd(ssl, client); //Set connection state to SSL socket
			Servlet(ssl); //Service connection
		}
		close(server); //Close server socket
		SSL_CTX_free(ctx); //Release context
	}
}

//Generate certificate, private key to be signed 
// int i = system("yes '' | openssl req -config openssl-server.cnf -newkey rsa:2048 -sha256 -nodes -out servercert.csr -outform PEM");
