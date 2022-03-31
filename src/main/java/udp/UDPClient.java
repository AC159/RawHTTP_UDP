package udp;

import org.apache.commons.cli.*;
import org.json.JSONObject;

import java.io.*;
import java.net.*;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.channels.DatagramChannel;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;

import static java.nio.channels.SelectionKey.OP_READ;
import static java.nio.charset.StandardCharsets.UTF_8;

public class UDPClient {

    public static boolean verbose = false;
    public static final int TIMEOUT = 1000; // timeout value in milliseconds

    public static void httpcHelp(String helpType) { // helpType can be "get" or "post"
        if (helpType.equalsIgnoreCase("get")) {
            System.out.println("usage: httpc.httpc get [-v] [-h key:value] URL\n" +
                    "Get executes a HTTP GET request for a given URL.\n" +
                    "\t-v \t Prints the detail of the response such as protocol, status and headers.\n" +
                    "\t-h key:value \t Associates headers to HTTP Request with the format 'key:value'.\n"+
                    "\t--router-port router port \t Specify the port on which the router is running.\n" +
                    "\t--router-host router hostname \t Specify the hostname (IP address or localhost) of the router.\n" +
                    "\t--server-port server port \t Specify the port on which the server is running.\n" +
                    "\t--server-host server hostname \t Specify the hostname (IP address or localhost) of the server.\n"
            );
        } else if (helpType.equalsIgnoreCase("post")) {
            System.out.println("usage: httpc.httpc post [-v] [-h key:value] [-d inline-data] [-f file] URL\n" +
                    "Post executes a HTTP POST request for a given URL with inline data or from file.\n" +
                    "\t-v \t Prints the detail of the response such as protocol, status and headers.\n" +
                    "\t-h key:value \t Associates headers to HTTP Request with the format 'key:value'.\n" +
                    "\t-d string \t Associates an inline data to the body HTTP POST request.\n" +
                    "\t-f file \t Associates the content of a file to the body HTTP POST request.\n" +
                    "Either [-d] or [-f] can be used but not both.\n" +
                    "\t--router-port router port \t Specify the port on which the router is running.\n" +
                    "\t--router-host router hostname \t Specify the hostname (IP address or localhost) of the router.\n" +
                    "\t--server-port server port \t Specify the port on which the server is running.\n" +
                    "\t--server-host server hostname \t Specify the hostname (IP address or localhost) of the server.\n");
        } else {
            System.out.println("httpc.httpc is a curl-like application but supports HTTP protocol only.\n" +
                    "Usage:\n" +
                    "\thttpc.httpc command [arguments]\n" +
                    "The commands are:\n" +
                    "\tget \t executes a HTTP GET request and prints the response.\n" +
                    "\tpost \t executes a HTTP POST request and prints the response.\n" +
                    "\thelp \t prints this screen.\n" +
                    "\t--router-port router port \t Specify the port on which the router is running.\n" +
                    "\t--router-host router hostname \t Specify the hostname (IP address or localhost) of the router.\n" +
                    "\t--server-port server port \t Specify the port on which the server is running.\n" +
                    "\t--server-host server hostname \t Specify the hostname (IP address or localhost) of the server.\n" +
                    "Use \"httpc.httpc help [command]\" for more information about a command.");
        }
    }

    public static HashMap<String, String> receiveResponse(List<String> httpMessage) throws NoSuchElementException, IOException {
        // this hashmap will contain all the extracted request headers
        HashMap<String, String> headers = new HashMap<>();

        String httpRequest = String.join("", httpMessage);
        if (verbose) System.out.println("HTTP request: \n" + httpRequest);

        // extract the headers of the http message
        String[] tokens = httpRequest.split("\r\n");
        System.out.println("Tokens: \n" + Arrays.toString(tokens));

        // From the request-line we can extract the method, version and uri of the http request
        String[] requestLineTokens = tokens[0].split(" ");
        headers.put("httpVersion", requestLineTokens[0].split("/")[1]);
        headers.put("statusCode", requestLineTokens[1]);

        for (int i = 1; i < tokens.length; i++) {
            if (!tokens[i].isEmpty() || !tokens[i].isBlank()) {
                String[] header = tokens[i].split(":");
                if (header.length > 1) headers.put(header[0].trim().toLowerCase(), header[1].trim());
            }
        }

        if (headers.get("content-length") != null) {
            int contentLength = Integer.parseInt(headers.get("content-length"));

            if (verbose) System.out.println("Parsing request body with content-length of " + contentLength);
            headers.put("requestBody", tokens[tokens.length-1].trim());
        }

        if (verbose) {
            System.out.println("\nRaw http request: " + httpRequest);
            System.out.println("\nParsed request headers: " + headers);
        }
        return headers;
    }

    public static void terminateConnectionWithServer(DatagramChannel channel, InetSocketAddress peerAddress, SocketAddress routerAddress, long lastSequenceNum) {
        try {
            ByteBuffer buffer = ByteBuffer.allocate(Packet.MAX_LEN).order(ByteOrder.BIG_ENDIAN);

            Selector selector = Selector.open();
            SelectionKey key = channel.register(selector, OP_READ);

            // Send FIN packet
            System.out.println("\nSending FIN packet to server...");
            Packet fin = new Packet(4, lastSequenceNum, peerAddress.getAddress(), peerAddress.getPort(), new byte[0]);
            channel.send(fin.toBufferArray(), routerAddress);

            while(true) {
                selector.select(TIMEOUT);
                Set<SelectionKey> keys = selector.selectedKeys();
                if (keys.isEmpty()) {
                    // Send FIN packet again
                    System.out.println("Timeout on FIN packet, sending packet again...");
                    channel.send(fin.toBufferArray(), routerAddress);
                } else {
                    // check for FIN-ACK response
                    channel.receive(buffer);
                    buffer.flip();
                    Packet ack = Packet.fromBuffer(buffer);
                    System.out.println("Server response to FIN packet: " + ack);
                    if (ack.getType() == 1 && ack.getSequenceNumber() == fin.getSequenceNumber()) {
                        System.out.println("Server ACKed FIN packet...");
                        break;
                    } else {
                        System.out.println("Received packet from server other than expected ACK...");
                        // ACK the packet if the server is still sending DATA packets. This means the server has not received all the ACKs for the DATA packets
                        if (ack.getType() == 0) {
                            Packet anotherAck = new Packet(1, ack.getSequenceNumber(), ack.getPeerAddress(), ack.getPeerPort(), new byte[0]);
                            channel.send(anotherAck.toBufferArray(), routerAddress);
                        }
                    }
                }
                keys.clear();
                buffer.clear();
            }

            // Now we know the server is aware that the client wants to terminate the connection, we can now wait for the server to send the final FIN
            Packet finalAck = new Packet(1, lastSequenceNum+1, peerAddress.getAddress(), peerAddress.getPort(), new byte[0]);

            // Send ACK to the server's FIN & wait for 2 timeouts
            channel.send(finalAck.toBufferArray(), routerAddress);
            int count = 0;

            while(true) {
                selector.select(TIMEOUT);
                Set<SelectionKey> keys = selector.selectedKeys();
                if (keys.isEmpty()) {
                    if (count >= 3) break;
                    else count++;
                } else {
                    channel.receive(buffer);
                    buffer.flip();
                    Packet p = Packet.fromBuffer(buffer);
                    System.out.println("Received server response just before terminating: " + p);
                    // Send the final ACK again since the server keeps sending packets which means it did not receive the final ACK to its FIN request
                    if (p.getType() == 4) channel.send(finalAck.toBufferArray(), routerAddress);
                }
                buffer.clear();
                keys.clear();
            }

            // We can now remove the selector and close the connection
            key.cancel();
            channel.close();
        } catch (IOException e) {
            System.out.println("Could not terminate connection with the server...");
            System.out.println(e.getMessage());
            System.exit(0);
        }
    }

    public static void main(String[] args) {

        if (args.length == 0 || args[0].equalsIgnoreCase("help") || (!args[0].equalsIgnoreCase("get") &&
                !args[0].equalsIgnoreCase("post"))) {
            System.out.println("Missing either GET or POST option...");
            httpcHelp("");
            System.exit(0);
        }

        Options options = new Options();
        options.addOption("v", false, "Prints the detail of the response such as protocol, status and headers.");
        options.addOption("h", true, "key:value \t Associates headers to HTTP Request with the format 'key:value'.");
        options.addOption("d", true, "string \t Associates an inline data to the body HTTP POST request.");
        options.addOption("f", true, "file \t Associates the content of a file to the body HTTP POST request.");
        options.addOption(null, "router-port", true, "router port \t Specify the port on which the router is running.");
        options.addOption(null, "router-host", true, "router hostname \t Specify the hostname (IP address or localhost) of the router.");
        options.addOption(null, "server-port", true, "server port \t Specify the port on which the server is running.");
        options.addOption(null, "server-host", true, "server hostname \t Specify the hostname (IP address or localhost) of the server.");

        CommandLineParser parser = new DefaultParser();
        CommandLine cmd = null;

        try {
            cmd = parser.parse(options, args);
        } catch (ParseException e) {
            System.out.println("Could not parse command line arguments...");
            System.out.println(e.getMessage());
            System.exit(1);
        }

        String[] headers = null;
        String url = args[args.length-1];
        String httpMethod = args[0];
        String data = null;
        int routerPort = -1;
        int serverPort = -1;
        String routerHost = null;
        String serverHost = null;
        String filePath = null;
        String fileData = null;
        String[] queryParameters = null;

        // validate command-line parameters
        if (httpMethod.equalsIgnoreCase("get") && args[1].equalsIgnoreCase("help")) {
            httpcHelp("get");
            System.exit(0);
        }
        if (httpMethod.equalsIgnoreCase("post") && args[1].equalsIgnoreCase("help")) {
            httpcHelp("post");
            System.exit(0);
        }
        if (httpMethod.equalsIgnoreCase("get") && (cmd.hasOption("d") || cmd.hasOption("f"))) {
            System.out.println("Invalid parameters specified...");
            System.out.println("Options -d and -f are not valid for GET requests.");
            httpcHelp("get");
            System.exit(0);
        }
        if (httpMethod.equalsIgnoreCase("post") && !cmd.hasOption("d") && !cmd.hasOption("f")) {
            System.out.println("Invalid parameters specified...");
            System.out.println("Options -d or -f must be specified for POST requests.\n");
            httpcHelp("post");
            System.exit(0);
        }
        if (httpMethod.equalsIgnoreCase("post") && cmd.hasOption("d") && cmd.hasOption("f")) {
            System.out.println("Invalid parameters specified...");
            System.out.println("Either -d or -f must be specified for POST requests.\n");
            httpcHelp("post");
            System.exit(0);
        }
        if (!cmd.hasOption("--router-port")) {
            System.out.println("--router-port argument must be specified");
            httpcHelp("");
            System.exit(0);
        }
        if (!cmd.hasOption("--router-host")) {
            System.out.println("--router-host argument must be specified");
            httpcHelp("");
            System.exit(0);
        }
        if (!cmd.hasOption("--server-port")) {
            System.out.println("--server-port argument must be specified");
            httpcHelp("");
            System.exit(0);
        }
        if (!cmd.hasOption("--server-host")) {
            System.out.println("--server-host argument must be specified");
            httpcHelp("");
            System.exit(0);
        }

        if (cmd.hasOption("v")) {
            verbose = true;
            System.out.println("Setting verbose option...");
        }
        if (cmd.hasOption("h")) {
            headers = cmd.getOptionValues("h");
            System.out.println("Headers: " + Arrays.toString(headers));
        }
        if (cmd.hasOption("d")) {
            data = cmd.getOptionValue("d");
            System.out.println("POST data: " + data);
        }
        if (cmd.hasOption("f")) {
            filePath = cmd.getOptionValue("f");
            System.out.println("POST file path: " + filePath);
        }
        // parse router & server hostnames and port numbers
        routerPort = Integer.parseInt(cmd.getOptionValue("--router-port"));
        System.out.println("Router port number: " + routerPort);

        routerHost = cmd.getOptionValue("--router-host");
        System.out.println("Router hostname: " + routerHost);

        serverPort = Integer.parseInt(cmd.getOptionValue("--server-port"));
        System.out.println("Server port number: " + serverPort);

        serverHost = cmd.getOptionValue("--server-host");
        System.out.println("Server hostname: " + serverHost);

        // Build the query to send to the server
        String startLine = httpMethod.toUpperCase() + " " + url + " HTTP/1.0\r\n";
        StringBuilder query = new StringBuilder(startLine);

        if (headers != null) {
            for(String header : headers) {
                if (header != null) query.append(header).append("\r\n");
            }
        }

        // Data for post request
        if (httpMethod.equalsIgnoreCase("post")) {
            if (data != null) {
                JSONObject json = new JSONObject(data);
                System.out.println("JSON: " + json);
                // add blank line before the body of the post request
                query.append("Content-Length:").append(json.toString().length()).append("\r\n");
                query.append("\r\n").append(json).append("\r\n");
            } else if (filePath != null) {
                try {
                    fileData = Files.readString(Path.of(filePath));
                    query.append("Content-Length:").append(fileData.length()).append("\r\n");
                    query.append("\r\n").append(fileData).append("\r\n");
                } catch (IOException e) {
                    System.out.println("Error reading file... " + e);
                    System.exit(1);
                }
            }
        }

        System.out.println("\nPerforming query: \n");
        System.out.println(query);
        System.out.println("Sending packet of length: " + query.length());

        // Convert router & server hostnames and ports into Inet addresses
        InetSocketAddress serverAddress = new InetSocketAddress(serverHost, serverPort);
        SocketAddress routerAddress = new InetSocketAddress(routerHost, routerPort);

        List<Packet> packetsToSend = Packet.splitMessageIntoPackets(query, serverAddress);

        DatagramChannel channel = null;
        try {
            channel = DatagramChannel.open();
        } catch (IOException exception) {
            System.out.println("Error creating a datagram channel...");
            System.exit(0);
        }

        // =================================== Performing 3-way handshake with the server ===================================

        System.out.println("Performing 3-way handshake with the server...");
        // Create SYN packet
        Packet syn = new Packet(2, 1, serverAddress.getAddress(), serverAddress.getPort(), new byte[0]);

        ByteBuffer buffer = ByteBuffer.allocate(Packet.MAX_LEN).order(ByteOrder.BIG_ENDIAN);
        try {
            channel.send(syn.toBufferArray(), routerAddress);

            // channel will be in non-blocking mode. That way, we can implement the timer functionality for each datagram
            channel.configureBlocking(false);
            Selector selector = Selector.open();

            // register the channel on the selector and listen for READ events on the channel (when the line has data on it)
            SelectionKey key = channel.register(selector, OP_READ);
            while(true) {
                // start timer on the SYN datagram that was sent
                selector.select(TIMEOUT);
                Set<SelectionKey> keys = selector.selectedKeys();
                // send SYN datagram again if we haven't received anything
                if (keys.isEmpty()) {
                    System.out.println("Timeout on SYN request, sending SYN request again...");
                    channel.send(syn.toBufferArray(), routerAddress);
                }
                else {
                    keys.clear();
                    break;
                }
            }

            // At this point we know the server has sent a response to the SYN datagram
            buffer.clear();
            channel.receive(buffer);
            buffer.flip();
            Packet response = Packet.fromBuffer(buffer);
            System.out.println("Server SYN-ACK response: ");
            System.out.println(response);
            if (response.getType() == 3) {
                // received a syn-ack from the server & we can send an ACK again
                System.out.println("Sending final ACK packet to complete 3-way handshake...");
                Packet ack = new Packet(1, 2, serverAddress.getAddress(), serverAddress.getPort(), new byte[0]);
                channel.send(ack.toBufferArray(), routerAddress);
                // Wait for server response to ACK datagram
                while(true) {
                    // start timer on the ACK datagram that was sent
                    selector.select(TIMEOUT);
                    Set<SelectionKey> keys = selector.selectedKeys();
                    // send ACK datagram again if we haven't received anything
                    if (keys.isEmpty()) {
                        System.out.println("Timeout on ACK request, sending ACK request again...");
                        channel.send(ack.toBufferArray(), routerAddress);
                    } else {
                        // receive the final ACK packet from the server for the 3-way handshake
                        channel.receive(buffer);
                        buffer.flip();
                        Packet finalAck = Packet.fromBuffer(buffer);
                        System.out.println("Received 3-way handshake confirmation from server: " + finalAck);
                        buffer.clear();
                        keys.clear();
                        break;
                    }
                    buffer.clear();
                    keys.clear();
                }
            }

            System.out.println("3-WAY HANDSHAKE HAS BEEN ESTABLISHED!");
            // =================================== Sending http request to server ===================================

            // Once the 3-way handshake has been established, we can send the datagrams associated with the http request
            System.out.println("Sending http request to server...");
            for (Packet p: packetsToSend) {
                try {
                    channel.send(p.toBufferArray(), routerAddress);
                    // wait for ACK for that packet or resend it in case of timeout
                    while(true) {
                        selector.select(TIMEOUT);
                        Set<SelectionKey> keys = selector.selectedKeys();
                        if (keys.isEmpty()) {
                            System.out.println("Timeout on datagram, sending datagram again...: " + p);
                            channel.send(p.toBufferArray(), routerAddress);
                        } else {
                            channel.receive(buffer);
                            buffer.flip();
                            Packet ack = Packet.fromBuffer(buffer);
                            // check if we have received an ACK for the correct packet or if we start receiving data from the server, it means the server has
                            // already processed our request
                            if ((p.getSequenceNumber() == ack.getSequenceNumber() && ack.getType() == 1) || ack.getType() == 0) {
                                System.out.println("Received ACK from server: " + ack);
                                break;
                            }
                        }
                        buffer.clear();
                        keys.clear();
                    }
                } catch (IOException exception) {
                    System.out.println("Error sending datagram packet to socket...");
                    System.out.println(exception.getMessage());
                    System.exit(0);
                }
            }

            // =================================== Receiving response from the server ===================================
            // Remove selector on the datagram channel since we are now going to receive packets from the server (the client is now becoming the "server")
            key.cancel();
            channel.configureBlocking(true);

            List<String> httpMessage = new ArrayList<>();
            List<Long> receivedPackets = new ArrayList<>();
            boolean transferFinished = false;
            System.out.println("Ready to receive response from server...");

            while (!transferFinished) {
                buffer.clear();

                // Wait for server response appearing on the channel
                channel.receive(buffer);

                // Parse a packet from the received raw data.
                buffer.flip();
                Packet packet = Packet.fromBuffer(buffer);
                System.out.println("Received packet: " + packet);

                // Extract parameters from packet
                String payload = new String(packet.getPayload(), UTF_8);
                InetAddress peerAddress = packet.getPeerAddress();
                int peerPort = packet.getPeerPort();
                long sequenceNumber = packet.getSequenceNumber();
                int type = packet.getType();

                if (type == 1) continue;

                // send back an ACK packet to acknowledge receipt
                Packet ack = new Packet(1, sequenceNumber, peerAddress, peerPort, new byte[0]);
                System.out.println("Sending ACK packet...");
                channel.send(ack.toBufferArray(), routerAddress);

                if (!receivedPackets.contains(sequenceNumber)) {
                    httpMessage.add(payload);
                    receivedPackets.add(sequenceNumber);
                }
                buffer.flip();

                if (payload.endsWith("\r\n")) {
                    System.out.println("END OF PACKET!");
                    System.out.println("Data: " + httpMessage);
                    HashMap<String, String> parsedMessage = receiveResponse(httpMessage);

                    System.out.println("Server response: ");
                    System.out.println(parsedMessage.get("requestBody"));

                    // Switch datagram channel back to non-blocking mode
                    key.cancel();
                    channel.configureBlocking(false);

                    // Terminate connection with server
                    terminateConnectionWithServer(channel, new InetSocketAddress(peerAddress, peerPort),  routerAddress, receivedPackets.get(receivedPackets.size()-1));
                    transferFinished = true;
                }
            }

        } catch (IOException e) {
            System.out.println(e.getMessage());
        }

    }
}
