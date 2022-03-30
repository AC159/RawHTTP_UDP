# Raw Http Client and Server using the UDP Protocol

## 1) Overview

### Communication model between the client and the server over an unreliable network
![Communication model between client-router-server](https://github.com/AC159/RawHTTP_UDP/blob/master/readme_images/communication_model.png?raw=true)

### Structure of UDP packets that are exchanged between client-router-server

![Packet structure](https://github.com/AC159/RawHTTP_UDP/blob/master/readme_images/packet_structure.png?raw=true)

### Communication flow example

![Communication flow](https://github.com/AC159/RawHTTP_UDP/blob/master/readme_images/flow_example.png?raw=true)


## 2) Building the project
  
### Building the router program that sits in-between the client and the server (Golang must be installed)

     cd router/source
     go build router.go
     
### Build the udp client and server programs

    mvn package
    
## 3) Running the project

### Start the router program

    Run router without drop rate & no packet delay:
    ./router --port=3000 --drop-rate=0 --max-delay=0 --seed=1

    Add drop rate & packet delay:
    ./router --port=3000 --drop-rate=0.2 --max-delay=10ms --seed=1
    
    Get help:
    ./router --help

### Start the server

    java -cp target/UDP_RawHttp-1.0-SNAPSHOT-jar-with-dependencies.jar udp.UDPServer -p 8007 -v --router-host localhost --router-port 3000
    
### Start the client

    GET request:
    java -cp target/UDP_RawHttp-1.0-SNAPSHOT-jar-with-dependencies.jar udp.UDPClient get --router-host localhost --router-port 3000 --server-host localhost --server-port 8007 http://127.0.0.1
    POST file to the UDP server:
    java -cp target/UDP_RawHttp-1.0-SNAPSHOT-jar-with-dependencies.jar udp.UDPClient post --router-host localhost --router-port 3000 --server-host localhost --server-port 8007 -f <path to file> http://127.0.0.1/newFile.txt
