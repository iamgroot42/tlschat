// Author : iamgroot42

#include <bits/stdc++.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netdb.h>
#include <unistd.h>
#include <sys/sendfile.h>
#include <arpa/inet.h>

#define CA_PORT 5011 //Port for CA signing/exchange
#define RELAY_PORT 5013 //Port for normal communication
#define BUFFER_SIZE 1024 //Maximum size per message

using namespace std;

// Create a 1-1 mapping between current socket and username (for efficient access)
map<string,int> name_id;
map<int,string> id_name;
// A set of FDs of currently active users
set<int> active_users;
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

// String representation of all users currently online
string online_users(){
    string ret_val = "";
    for (set<int>::iterator it=active_users.begin(); it!=active_users.end(); ++it){
    ret_val += id_name[*it] + "\n";
    }
    return ret_val.substr(0, ret_val.size()-1);
}

// Client ended connection; remove everything associated with them
void remove_user(int c){
    active_users.erase(c);
    name_id.erase(id_name[c]);
    id_name.erase(c);
    // Close this connection
    close(c);
}

// A thread spawned per connection, to handle all incoming requests from there
void* per_user(void* void_connfd){
    string current_username;
    long connfd = (long)void_connfd;
    int ohho = 0;
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
        if(!command.compare("/identify")){
            pch = strtok_r (NULL, " ", &STRTOK_SHARED);
            string username(pch);
            name_id[username] = connfd;
            id_name[connfd] = username;
            active_users.insert(connfd);
            send_data("Identified as " + username + " !", connfd);
        }
        else if(!command.compare("/connect")){
            pch = strtok_r (NULL, " ", &STRTOK_SHARED);
            string destination(pch);
            try{
                send_data("/listen", name_id[destination]);
            }
            catch(...){
                send_data("Requested user not online", connfd);
            }
        }
        else if(!command.compare("/who")){
            send_data(online_users().c_str(), connfd);
        }
        else if(!command.compare("/exit")){
            remove_user(connfd); // Remove active-user
            return 0; //End thread;
        }
    }
}


void* ca_thread(void* useless_arg){
    int sys_ret, listenfd = 0,ohho = 0;
    char buffer[BUFFER_SIZE];
    long connfd = 0;
    sockaddr_in serv_addr; 
    listenfd = socket(AF_INET, SOCK_STREAM, 0);
    memset(&serv_addr, '0', sizeof(serv_addr)); 
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    serv_addr.sin_port = htons(CA_PORT); 
    bind(listenfd, (struct sockaddr*)&serv_addr, sizeof(serv_addr)); 
    listen(listenfd, 15);
    while(1){
        connfd = accept(listenfd, (struct sockaddr*)NULL, NULL);
        char* STRTOK_SHARED;
        ohho = 0;
        memset(buffer,'0',sizeof(buffer));
        ohho = read(connfd,buffer,sizeof(buffer));
        buffer[ohho] = 0;
        // Extract command type from incoming data
        char *pch = strtok_r(buffer," ", &STRTOK_SHARED);
        string command(pch);
        if(!command.compare("/CSR")){
            // Extract certificate, save to file
            string certificate(STRTOK_SHARED);
            ofstream out("servercert.csr");
            out << certificate;
            out.close();
            // Sign certificate
            sys_ret = system("yes | openssl ca -config ca_files/openssl-ca.cnf -policy signing_policy -extensions signing_req -out servercert.pem -infiles servercert.csr >> /dev/null");
            sleep(2);
            //Read file
            ifstream is("servercert.pem");
            string read_cert;
            is.seekg(0, ios::end);
            read_cert.resize(is.tellg());
            is.seekg(0, ios::beg);
            is.read(&read_cert[0], read_cert.size());
            is.close();
            send_data(read_cert.c_str(),connfd);
        }
        else{
            send_data("invalid request",connfd);   
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
    serv_addr.sin_port = htons(RELAY_PORT); 
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
