# Raw Http Client and Server using the UDP Protocol

## 1) Overview


## 2) Building the project
  
### Building the router program that sits in-between the client and the server (Golang must be installed)

     cd router/source
     go build router.go
     
### Build the udp client and server programs

    mvn package
    
## 3) Running the project

### Start the router program

    ./router --port=3000 --drop-rate=0.2 --max-delay=10ms --seed=1
    or
    ./router --help

### Start the server

    java -cp target/UDP_RawHttp-1.0-SNAPSHOT-jar-with-dependencies.jar udp.UDPServer -p 8007 -v
    
### Start the client

    java -cp target/UDP_RawHttp-1.0-SNAPSHOT-jar-with-dependencies.jar udp.UDPClient --router-host localhost --router-port 3000 --server-host localhost --server-port 8007
