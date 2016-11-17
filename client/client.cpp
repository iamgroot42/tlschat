// Author : iamgroot42

#include <bits/stdc++.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/sendfile.h>
#include <netinet/in.h>
#include <netdb.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <mcrypt.h>

#define REGISTER_PORT 5009 //Port for registrations
#define KDC_PORT 5010 //Port for normal communication
#define CA_PORT 5011 //Port for communication with CA
#define BUFFER_SIZE 1024 //Maximum size per message
#define CHALLENGE "potato"
#define HARDCODED_IV "0123456789123456"

// Reference for enc/dec : https://gist.github.com/bricef/2436364

using namespace std;

struct arg_struct{
    int sock1;
    int sock2;
};

string encrypt(string data, string keye, string IVe){
    int buffer_len = 16;
    int mbl = buffer_len*((data.length()/buffer_len) + 1);
    char* bass = (char*)calloc(1, mbl);
    strncpy(bass, data.c_str(), data.length());
    char *IV = strdup(IVe.c_str()), *key = strdup(keye.c_str());
    int key_len = keye.length();
    string output = "";
    for(int i=0; i < mbl; i += buffer_len){
        char* bufferr = (char*)calloc(1, buffer_len);
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
    char* bass = (char*)calloc(1, mbl);
    strncpy(bass, data.c_str(), data.length());
    char *IV = strdup(IVe.c_str()), *key = strdup(keye.c_str());
    int key_len = keye.length();
    string output = "";
    for(int i=0; i < mbl; i += buffer_len){
        char* bufferr = (char*)calloc(1, buffer_len);
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

// Indicator variables for status of server connection, login status
bool server_down = false, logged_in = false;
map<string,string> shared_keys;
map<string, string> sent_nonce;
set<string> good_to_go;
string my_username, my_private_key;

// Send data via the given socket-fd
int send_data(string data, int sock){
    const char* commy = data.c_str();
    if( (write(sock, commy, strlen(commy)) < 0) ){
        return 0;
    }
    return 1;
}

void* ca_feedback(void* arguments){
	arg_struct *args = (arg_struct *)arguments;
	long listenfd = args->sock1;
	long cafd = args->sock2;
	char buffer[BUFFER_SIZE];
	char* STRTOK_SHARED;
	int ohho = 0;
	while(1){
		memset(buffer,'0',sizeof(buffer));
		ohho = read(cafd,buffer,sizeof(buffer));
		// If server shuts down/terminates connection
		if(!ohho){
			cout<<">> Connection with CA server terminated!"<<endl;
			server_down = true;
			close(cafd);
			return 0;
		}
		buffer[ohho] = 0;
		char *pch = strtok_r(buffer," ", &STRTOK_SHARED);
		string command(pch);
		if(!command.compare("/SIGNED")){
			pch = strtok_r (NULL, " ", &STRTOK_SHARED);
			string alice(pch), iv(HARDCODED_IV);
			srand(time(NULL));
			long nonce_B = long(rand());
			sent_nonce[alice] = to_string(nonce_B);
			string encrypted_packet = encrypt(alice + " " + to_string(nonce_B), my_private_key, iv);
			// Generate a nonce and return it with A, encrypted with Kbs
			string ret_ticket = "/SERVER_HELLO " + alice  + " " + encrypted_packet;
			send_data(ret_ticket, cafd);
		}
		else if(!command.compare("/CSR_RESPONSE")){
			// pch = strtok_r(NULL, " ", &STRTOK_SHARED);
			// If response indicates valid certificate, ask that server for DH parameters
			string data = "/PARAM_REQ";
			send_data(data, listenfd);	
		}
		else{
			if(!strcmp("Signed-in!",buffer)){
				logged_in = true;
			}
			cout<<">> "<<buffer<<endl;
		}
	}
}

// Thread to read incoming data (from server)
void* server_feedback(void* arguments){
	arg_struct *args = (arg_struct *)arguments;
	long listenfd = args->sock1;
	long cafd = args->sock2;
	char buffer[BUFFER_SIZE];
	char* STRTOK_SHARED;
	int ohho = 0;
	while(1){
		memset(buffer,'0',sizeof(buffer));
		ohho = read(listenfd,buffer,sizeof(buffer));
		// If server shuts down/terminates connection
		if(!ohho){
			cout<<">> Connection with server terminated!"<<endl;
			server_down = true;
			close(listenfd);
			return 0;
		}
		buffer[ohho] = 0;
		char *pch = strtok_r(buffer," ", &STRTOK_SHARED);
		string command(pch);
		if(!command.compare("/CLIENT_HELLO")){
			pch = strtok_r (NULL, " ", &STRTOK_SHARED);
			string alice(pch), iv(HARDCODED_IV);
			srand(time(NULL));
			long nonce_B = long(rand());
			sent_nonce[alice] = to_string(nonce_B);
			string encrypted_packet = encrypt(alice + " " + to_string(nonce_B), my_private_key, iv);
			// Generate a nonce and return it with A, encrypted with Kbs
			string ret_ticket = "/SERVER_HELLO " + alice  + " " + encrypted_packet;
			send_data(ret_ticket, listenfd);
		}
		else if(!command.compare("/SERVER_HELLO")){
			pch = strtok_r(NULL, " ", &STRTOK_SHARED);
			// Check certificate with CA. If certificate is valid, send ask server to send DH params
			string send = "CA extracted from server hello";
			send_data(send, ca_sock);
			string bob(pch);
			string b_ticket(STRTOK_SHARED);
			// srand(time(NULL));
			// sent_nonce[bob] = to_string(long(rand()));
			// send_data(send, listenfd);
			// Check public certificate with CA, respond accordingly
		}
		else if(!command.compare("/PARAM_REQ")){
			pch = strtok_r(NULL, " ", &STRTOK_SHARED);
			// Check certificate with CA. If certificate is valid, send ask server to send DH params
			string send = "/DH_PARAM Send DH Params";
			string bob(pch);
			string b_ticket(STRTOK_SHARED);
			// srand(time(NULL));
			// sent_nonce[bob] = to_string(long(rand()));
			send_data(send, listenfd);
		}
		else if(!command.compare("/DH_PARAM")){
			pch = strtok_r(NULL, " ", &STRTOK_SHARED);
			// Check certificate with CA. If certificate is valid, send ask server to send DH params
			string send = "/DH_PARAM_2 Send DH Params";
			string bob(pch);
			string b_ticket(STRTOK_SHARED);
			// srand(time(NULL));
			// sent_nonce[bob] = to_string(long(rand()));
			send_data(send, listenfd);
		}
		else if(!command.compare("/DH_PARAM_2")){
			pch = strtok_r(NULL, " ", &STRTOK_SHARED);
			// Check certificate with CA. If certificate is valid, send ask server to send DH params
			string send = "/okay";
			string bob(pch);
			string b_ticket(STRTOK_SHARED);
			// srand(time(NULL));
			// sent_nonce[bob] = to_string(long(rand()));
			send_data(send, listenfd);
		}
		else if(!command.compare("/okay")){
			pch = strtok_r (NULL, " ", &STRTOK_SHARED);
			string bob(pch);
			// we can now start exchanging encrypted messages with bob
			good_to_go.insert(bob);
		}
		else if(!command.compare("/msg")){
			pch = strtok_r (NULL, " ", &STRTOK_SHARED);
			string bob(pch);
			string iv(HARDCODED_IV);
			string data(STRTOK_SHARED);
			string message = decrypt(data, shared_keys[bob], iv);
			char *dup = strdup(message.c_str());
			char* pch2 = strtok_r (dup, " ", &STRTOK_SHARED);
			string enc_len(pch2);
			string real_message(STRTOK_SHARED);
			// Check if message has been tampered or not
			if(!enc_len.compare(to_string(real_message.length()))){
				string printout = "(" + bob + ") " + real_message;
				cout<<">> "<<printout<<endl;	
			}
			else{
				cout<<">> Tampered message received!"<<endl;
			}
		}
		else{
			if(!strcmp("Signed-in!",buffer)){
				logged_in = true;
			}
			cout<<">> "<<buffer<<endl;
		}
	}
}

// Create a socket connection for the given IP and port
int create_socket_and_connect(char* address, int port){
	int sock = 0;
	struct sockaddr_in serv_addr;
	if((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0){
        cerr<<">> Socket creation error"<<endl;
        return 0;
    } 
	memset(&serv_addr, '0', sizeof(serv_addr)); 
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(port); 
    if(inet_pton(AF_INET, address, &serv_addr.sin_addr)<=0){
        cerr<<">> Invalid address"<<endl;
        return 0;
    } 
    if( connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0){
        cerr<<">> Connection Failed"<<endl;
        return 0;
    }
    return sock;
}


int main(int argc, char *argv[]){
	// Argument: IP address of server
	if(argc<2){
		cout<<"Usage: "<<argv[0]<<" <server ip> <ca server ip>"<<endl;
		return 0;
	}
	// Establish connection
	long ca_sock,kdc_sock,register_sock;
	kdc_sock = create_socket_and_connect(argv[1], KDC_PORT);
	register_sock = create_socket_and_connect(argv[1], REGISTER_PORT);
	ca_sock = create_socket_and_connect(argv[2],CA_PORT);
    // Create thread for receiving messages on irc socket
	pthread_t pot;
	// Sending (relay server socket, CA server socket) to function
	arg_struct x;
	x.sock1 = kdc_sock;
	x.sock2 = ca_sock;
    pthread_create(&pot, NULL, server_feedback, (void*)x);
    // Create thread for receiving messages on register socket
	// pthread_t pot2;
    // pthread_create(&pot2, NULL, server_feedback, (void*)register_sock);
	string send, username, password, command;
	cout<<">> Welcome to kdchat!"<<endl;
	while(1){
		// Kill main thread if server is down.
		if(server_down){
			return 0;
		}
		cin>>command;
		if(!command.compare("/register") ){
			cin>>username;
			cin>>password;
			send = username + " " + password;
			if(!send_data(send, register_sock)){
				cout<<">> Error in registration. Please try again."<<endl;
			}
		}
		else if(!command.compare("/login")){	
			cin>>username;
			cin>>password;
			if(logged_in){
				cout<<">> Already logged in!"<<endl;
			}
			else{
				string iv(HARDCODED_IV);
				string challenge(CHALLENGE);
				send = "/login " + username + " " + encrypt(challenge,password,iv);
				if(!send_data(send, kdc_sock)){
					cout<<">> Error logging-in. Please try again."<<endl;
				}
				else{
					my_username = username;
					my_private_key = password;
				}
			}
		}
		else if(!command.compare("/exit")){
			// Communicate logout action to server
			bool kill = true;
			if(logged_in){
				if(!send_data(command ,kdc_sock)){
					cout<<">> Error logging out. Please try again."<<endl;
					kill = false;
				}
			}
			if(kill){
				// Kill thread listening for feedback
				pthread_kill(pot,0);
				close(kdc_sock);
				close(register_sock);
				cout<<">> Exiting!\nThanks for using IRsea!"<<endl;
				return 0;
			}
		}
		else if(!command.compare("/who") && logged_in){
			if(!send_data(command, kdc_sock)){
				cout<<">> Error communicating with server. Please try again."<<endl;
			}
		}
		else if(!command.compare("/msg") && logged_in){
			cin>>username;
			try{
				if(good_to_go.find(username) != good_to_go.end() && shared_keys.count(username)){
					getline(cin, password);
					string iv(HARDCODED_IV);
					password = to_string(password.length()) + " " + password;
					password = encrypt(password, shared_keys[username], iv);
					send = command + " " + username + " " + password;
				}
				else{
					cout<<">> Shared key not negotiated. Please run /CLIENT_HELLO."<<endl;
				}
				if(!send_data(send, kdc_sock)){
					cout<<">> Error communicating with server. Please try again."<<endl;
				}
			}
			catch(...){
				cout<<">> Shared key not negotiated. Please run /CLIENT_HELLO."<<endl;
			}
		}
		else if(!command.compare("/CLIENT_HELLO") && logged_in){
			cin>>username;
			send = "/CLIENT_HELLO " + username + " " + my_username;
			send_data(send, kdc_sock);
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
	return 0;
}
