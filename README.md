# tlschat
Multi-user chat based on TLS, with mutual authentication using X.509 certificates. Made as a course assignment for Network Security (CSE550)

## Working

### Server

* Three threads work in parallel.
* One thread acts as the CA.
* One thread clears the outgoing message queue by sending data to respective users.
* One thread creates a new thread (for communication) for every incoming request by the client. This thread is deleted once the client is done with their interaction with the server.


### Client
* Two threads work in parallel.
* One thread listens to the server for incoming data (which may be sent by the server itself, or data redirected by the server).
* One thread is for HCI; sending data to the server as the user requests.


## Running it
* Install `mcrypt` by running : `apt install libmcrypt-dev`
* To run the server, run:  ` make`. Then, run it as `./server` (from tls folder).
* To run a client, run:  ` make`. Then, run it as `./client <SERVER ADDRESS>` (from client folder)
* Run `make clean` to remove compiled programs.


## Specifics
* Default users (hello,world) & (test,user) for testing.
* Maximum length per message (before encryption): 10000 characters.
* strtok() is not thread safe (as standard implementation doesn't use TLS). Thus, strtok_r() has been used.


## Cases tested (& handled)
* A chatting with B (after TLS connection has been established).
* A trying to create a TLS channel with a certificate not signed by CA.
* MITM listening to all conversations (including negotiation of keys) : cannot decrypt them.
* MITM tampering with messages : detected at the recipient's end.
* A Trying to establish a TLS connection without identifying itself.


### Example (for client)
```
>> CSR sent to CA. Please wait...
>> Certificate signed!
/login test user
>> Signed-in!
/connect hello
>> You may now start talking!
/msg what's up?
>>  nothing much, you?
```
