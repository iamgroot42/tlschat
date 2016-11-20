// Author : iamgroot42
#include <bits/stdc++.h>
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
#include <mcrypt.h>

#define CA_PORT 5011 //Port for CA signing/exchange
#define TLS_PORT 5022 //Port for p2p communication
#define RELAY_PORT 5013 //Port for establishing communication with peer
#define BUFFER_SIZE 10000 //Maximum size per message
#define USER_FILENAME "users" //Filename containing username & passwords
#define CHALLENGE "potato"
#define HARDCODED_IV "0123456789123456"

bool logged_in = false, tls_established = false;
SSL_CTX *ctx_glob;
SSL *ssl_glob;

using namespace std;

string encrypt(string data, string keye, string IVe){
    int buffer_len = 16;
    int mbl = buffer_len*((data.length()/buffer_len) + 1);
    char* bass = (char*)calloc(1, mbl);
    strncpy(bass, data.c_str(), data.length());
    char *IV = strdup(IVe.c_str()), *key = strdup(keye.c_str());
    int key_len = keye.length();
    char* bufferr = (char*)calloc(1, buffer_len);
    string output = "";
    for(int i=0; i < mbl; i += buffer_len){
        memcpy(bufferr, bass+i, buffer_len);
        void* buffer = (void*)bufferr;
        MCRYPT td = mcrypt_module_open("rijndael-128", NULL, "cbc", NULL);
        mcrypt_generic_init(td, key, key_len, IV);
        mcrypt_generic(td, buffer, buffer_len);
        mcrypt_generic_deinit(td);
        mcrypt_module_close(td);
        output = output + (char*)buffer;
    }
    return output;
}

string decrypt(string data, string keye, string IVe){ 
    int buffer_len = 16;
    int mbl = data.length();
    char* bass = (char*)data.c_str();
    // strncpy(bass, data.c_str(), data.length());
    char *IV = strdup(IVe.c_str()), *key = strdup(keye.c_str());
    int key_len = keye.length();
    char* bufferr = (char*)calloc(1, buffer_len);
    string output = "";
    for(int i=0; i < mbl; i += buffer_len){
        memcpy(bufferr, bass+i, buffer_len);
        void* buffer = (void*)bufferr;
        MCRYPT td = mcrypt_module_open("rijndael-128", NULL, "cbc", NULL);
        mcrypt_generic_init(td, key, key_len, IV);
        mdecrypt_generic(td, buffer, buffer_len);
        mcrypt_generic_deinit(td);
        mcrypt_module_close(td);
        output = output + (char*)buffer;
    }
    return output;
}

// Send data back to the client
int send_data(string data, int sock)
{
    const char* commy = data.c_str();
    if( (write(sock, commy, strlen(commy)) < 0) )
    {
        return 0;
    }
    return 1;
}

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
	const SSL_METHOD *method;
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
	const SSL_METHOD *method;
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


// Thread to read incoming data (from server,peer)
void* server_feedback(void* void_listenfd){
	long listenfd = (long)void_listenfd;
	char buffer[BUFFER_SIZE];
	char* STRTOK_SHARED;
	int server, tls_init = 0,ohho = 0;
	while(!tls_init){
		memset(buffer,'0',sizeof(buffer));
		ohho = read(listenfd,buffer,sizeof(buffer));
		buffer[ohho] = 0;
		char *pch = strtok_r(buffer," ", &STRTOK_SHARED);
		cout<<">> "<<buffer;
		if(!strcmp(pch,"/listen")){
			tls_init = 1;
			close(listenfd);
		}
		else if(!strcmp(pch,"Signed-in!")){
			logged_in = true;
			cout<<">> Signed in!"<<buffer;
		}
	}
	//Start listening for incoming TLS connections
	ctx_glob = InitServerCTX(); //Initialize SSL
	// LoadCertificates(ctx, "temp_cert.pem", "temp_key.pem");
	LoadCertificates(ctx_glob, "servercert.pem", "serverkey.pem");
	server = OpenListener(TLS_PORT);
	struct sockaddr_in addr;
	int bytes, len = sizeof(addr);
	int client = accept(server,(struct sockaddr*)&addr, (socklen_t*)&len); //Accept connection as usual
	ssl_glob = SSL_new(ctx_glob);
	SSL_set_fd(ssl_glob, client);
	SSL_accept(ssl_glob);
	tls_established = true;
	while(1){
		bytes = SSL_read(ssl_glob, buffer, sizeof(buffer));
		if(bytes > 0){
			buffer[bytes] = 0;
			cout<<">> "<<buffer<<endl;
		}
	}
}

//Read incoming data on TLS connection
void* incoming_tls_data(void* useless){
	int bytes;
	char buffer[BUFFER_SIZE];
	while(1){
		bytes = SSL_read(ssl_glob, buffer, sizeof(buffer));
		if(bytes > 0){
			buffer[bytes] = 0;
			cout<<">> "<<buffer;
		}
	}
}

int main(int argc, char *argv[]){
	int server, ca, relay, ohho=0;
	char msg[BUFFER_SIZE];
	string command;
	int bytes;
	if(argc < 2){
		printf("Usage: %s <server_ip>\n",argv[0]);
		return 0;
	}
	relay = create_socket_and_connect(argv[1], RELAY_PORT);
	ca = create_socket_and_connect(argv[1], CA_PORT);
	pthread_t pot,pot2;
    pthread_create(&pot, NULL, server_feedback, (void*)relay);
    // Generate a CSR, get it signed by CA
    cout<<">> CSR sent to CA. Please wait..."<<endl;
	system("yes '' | openssl req -config openssl-server.cnf -newkey rsa:2048 -sha256 -nodes -out servercert.csr -outform PEM  > /dev/null 2>&1");
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
	cout<<">> Certificate signed!"<<endl;
	while(1){
		cin>>command;
		if(!command.compare("/connect") && logged_in){
			ctx_glob = InitCTX();
			ssl_glob = SSL_new(ctx_glob);
			string username;
			cin>>username;
			command = command + " " + username;
			send_data(command, relay);
			tls_established = true;
			// Sleep for 2 seconds (hack,for now)
			sleep(2);
			server = create_socket_and_connect("127.0.0.1", TLS_PORT);
			SSL_set_fd(ssl_glob, server);
			SSL_connect(ssl_glob);
			//Start listening for messages from peer
			pthread_create(&pot2, NULL, incoming_tls_data, NULL);
		}
		else if(!command.compare("/login")){
			string username, password;
			cin>>username;
			cin>>password;
			if(logged_in){
				cout<<">> Already logged in!"<<endl;
			}
			else{
				string iv(HARDCODED_IV);
				string challenge(CHALLENGE);
				string send = "/login " + username + " " + encrypt(challenge,password,iv);
				if(!send_data(send, relay)){
					cout<<">> Error logging-in. Please try again."<<endl;
				}
			}
		}
		else if(!command.compare("/exit")){
			pthread_kill(pot,0);
			close(relay);
			SSL_CTX_free(ctx_glob); //Release context
			close(server);
			cout<<">> Exiting!\nThanks for using IRsea!"<<endl;
			return 0;
		}
		else if(!command.compare("/msg")){
			if(!tls_established){
				cout<<">> Connect before you can start talking!"<<endl;
			}
			else{
				fgets(msg, BUFFER_SIZE, stdin);
				SSL_write(ssl_glob, msg, strlen(msg)); //Encrypt and send message
			}
		}
		else if(!command.compare("/who") && logged_in){
			send_data(command, relay);
		}
		else{
			if(!logged_in){
				cout<<">> Not logged in. Please log in first!"<<endl;
			}
			else{
				cout<<">> Invalid command! Please read the README for the list of supported commands"<<endl;
			}
		}
	}
}
