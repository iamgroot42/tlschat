// Author : iamgroot42

#include <bits/stdc++.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netdb.h>
#include <unistd.h>
#include <sys/sendfile.h>
#include <arpa/inet.h>
#include <mcrypt.h>

#define CA_PORT 5010 //Port for CA signing/exchange
#define BUFFER_SIZE 1024 //Maximum size per message
#define CHALLENGE "potato"
#define HARDCODED_IV "0123456789123456"


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

// Create a 1-1 mapping between current socket and username (for efficient access)
map<string,int> name_id;
map<int,string> id_name;
// A set of FDs of currently active users
set<int> active_users;
// Username-password mapping..stored as cache, written to memory when program ends
map<string, string> username_password;
// A queue which contains outgoing p2p data
queue< pair<int, string> > chat;

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

string random_string(int length){
    static const char alphanum[] ="0123456789!#$^&*ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    int stringLength = sizeof(alphanum) - 1;
    srand(time(NULL));
    string rand_str("");
    for(int i = 0; i < length; ++i){
        rand_str = rand_str + alphanum[rand() % stringLength];
    }
    return rand_str;
}


// A thread spawned per connection, to handle all incoming requests from there
void* per_user(void* void_connfd){
    string current_username;
    long connfd = (long)void_connfd;
    int ohho = 0, logged_in = 0;
    char buffer[BUFFER_SIZE];
    char* STRTOK_SHARED;
    while(1){
        memset(buffer,'0',sizeof(buffer));
        ohho = read(connfd,buffer,sizeof(buffer));
        if(!ohho){
             remove_user(connfd); // Remove active-user
             return 0; //End thread
        }
        buffer[ohho] = 0;
        cout<<"LOG : "<<buffer<<endl;
        // Extract command type from incoming data
        char *pch = strtok_r(buffer," ", &STRTOK_SHARED);
        string command(pch);
        logged_in = is_online(connfd);
        if(!command.compare("/login")){
            try{
                pch = strtok_r (NULL, " ", &STRTOK_SHARED);
                string username(pch);
                string iv(HARDCODED_IV);
                string enc(STRTOK_SHARED);
                string challenge(CHALLENGE);
                if(!decrypt(enc,username_password[username],iv).compare(challenge)){
                    send_data("Signed-in!", connfd);
                    // Update 1-1(effective) mapping of connectionID and username
                    current_username = username;
                    name_id[username] = connfd;
                    id_name[connfd] = username;
                    active_users.insert(connfd); // Update list of active users
                }
                else{
                    send_data("Error signing in!", connfd);
                }
            }
            catch(...){
                send_data("Malformed message!", connfd);
            }
        }
}

// Empties the send-queue by sending messages to respective clients
void* send_back(void* argv){
    pair<int, string> x;
    while(true){
        while(chat.size()){
            x = chat.front();
            chat.pop();
            send_data(x.second, x.first);
        } 
    }
}

// Main process
int main(){
    pthread_t pot;
    // Thread to handle out-going p2p messages
    pthread_create(&pot, NULL, send_back, NULL);
    // Main thread
    int listenfd = 0;
    long connfd = 0;
    sockaddr_in serv_addr; 
    listenfd = socket(AF_INET, SOCK_STREAM, 0);
    memset(&serv_addr, '0', sizeof(serv_addr)); 
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    serv_addr.sin_port = htons(KDC_PORT); 
    bind(listenfd, (struct sockaddr*)&serv_addr, sizeof(serv_addr)); 
    listen(listenfd, 15);
    while(1){
        connfd = accept(listenfd, (struct sockaddr*)NULL, NULL);
        // New thread per user (for communication)
        pthread_t pot_temp;
        pthread_create(&pot_temp, NULL, per_user, (void*)connfd);
    }
    return 0;
}
