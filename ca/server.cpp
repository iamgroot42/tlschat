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
#define BUFFER_SIZE 10000 //Maximum size per message

using namespace std;

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

// Main process
int main(){
    int sys_ret, listenfd = 0,ohho = 0;
    char buffer[BUFFER_SIZE];
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
        char* STRTOK_SHARED;
        oho = 0;
        memset(buffer,'0',sizeof(buffer));
        ohho = read(connfd,buffer,sizeof(buffer));
        buffer[ohho] = 0;
        cout<<"LOG : "<<buffer<<endl;
        // Extract command type from incoming data
        char *pch = strtok_r(buffer," ", &STRTOK_SHARED);
        string command(pch);
        if(!command.compare("/CHECK_CA")){
            //Receive certificate
            //Check it's validity
        }   
        else if(!command.compare("/CSR")){
            //Receive certificate, sign it
            // Extract certificate and save it
            sys_ret = system("yes | openssl ca -config ca_files/openssl-ca.cnf -policy signing_policy -extensions signing_req -out servercert.pem -infiles servercert.csr");
            send_data("sign ho gaya, re",connfd);
        }
        else{
            send_data("invalid request",connfd);   
        }
    }
    return 0;
}
