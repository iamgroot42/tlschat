# tlschat
Multi-user chat based on TLS, with mutual authentication using X.509 certificates. Made as a course assignment for Network Security (CSE550)

## Running it
* Install `mcrypt` by running : `apt install libmcrypt-dev`
* To run the server, run:  ` make`. Then, run it as `./server` (from server folder).
* To run a client, run:  ` make`. Then, run it as `./client <SERVER ADDRESS>` (from client folder)
* Run `make clean` to remove compiled programs.
