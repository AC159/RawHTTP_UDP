package udp;

import org.apache.commons.cli.*;

import java.io.*;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.channels.DatagramChannel;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static java.nio.charset.StandardCharsets.UTF_8;
import static udp.UDPClient.TIMEOUT;

public class UDPServer {
    public static boolean verbose = false;
    public static String directoryPath = System.getProperty("user.dir"); // get current working directory

    public static void printHttpfsHelp() {
        System.out.println("\nhttpfs is a simple file server.\n" +
                "usage: httpfs [-v] [-p PORT] [-d PATH-TO-DIR]\n" +
                "-v \tPrints debugging messages.\n" +
                "-p \tSpecifies the port number that the server will listen and serve at.\n" +
                "\tDefault is 8080.\n" +
                "-d \tSpecifies the directory that the server will use to read/write\n" +
                "\trequested files. Default is the current directory when\n" +
                "\tlaunching the application.\n" +
                "\t--router-port router port \t Specify the port on which the router is running.\n" +
                "\t--router-host router hostname \t Specify the hostname (IP address or localhost) of the router.\n" +
                "help \tPrints this help message");
    }

    public static List<String> getFiles() throws IOException {
        List<Path> files;
        Path path = Paths.get(directoryPath);
        Stream<Path> walk = Files.walk(path);
        files = walk.filter(Files::isRegularFile).collect(Collectors.toList());

        List<String> relativePaths = new ArrayList<>();
        for (Path p : files) {
            relativePaths.add(p.toString().replace(directoryPath + "/", ""));
        }

        if (verbose) {
            System.out.println("\nFiles found in " + path + " directory: ");
            System.out.println(relativePaths);
        }

        return relativePaths;
    }

    public static StringBuilder readFileContents(File file) {
        StringBuilder contents = new StringBuilder();
        try {
            Scanner sc = new Scanner(new FileInputStream(file));
            while (sc.hasNext()) {
                contents.append(sc.nextLine()).append("\n");
            }
        } catch (FileNotFoundException exception) {
            if (verbose) {
                System.out.println("Error reading file contents: " + exception.getMessage());
            }
            System.out.println("File not found");
        }
        return contents;
    }

    public static boolean isFilepathValid(String filepath) {
        // Verify that the provided filepath is inside the current working directory for security reasons
        File file = new File(filepath);
        boolean canWrite = file.canWrite();
        boolean containsWeirdPatterns = filepath.contains(".."); // detect for change of directory pattern i.e. "../"
        return !file.exists() || canWrite && !containsWeirdPatterns;
    }

    public static StringBuilder handleGetRequest(HashMap<String, String> headers) {

        StringBuilder response = new StringBuilder();
        StringBuilder body = new StringBuilder();

        // todo: return files with extensions that match the "Accept" key of the request header
        try {
            List<String> files = getFiles();
            for (String p : files) {
                if (headers.get("httpUri").equalsIgnoreCase("/") || headers.get("httpUri").equalsIgnoreCase("")) {
                    body.append("-").append(p).append("\n");
                } else if (("/"+p).equals(headers.get("httpUri")) || p.equals(headers.get("httpUri"))) {
                    body = readFileContents(new File(directoryPath + "/" + p));
                }
            }
        } catch (IOException e) {
            response = createHttpError(404, "Not Found", "File not found on the server\r\n");
        }

        if (!body.isEmpty()) {
            response.append("HTTP/1.0 200 OK\r\n");
            response.append("Content-Type: text/html\r\n");
            response.append("Content-Length: ").append(body.length()).append("\r\n").append("\n\n");
            response.append(body).append("\r\n");
        } else {
            response = createHttpError(404, "Not Found", "File not found on the server\r\n");
        }
        return response;
    }

    public static StringBuilder handlePostRequest(HashMap<String, String> headers) {
        StringBuilder response = new StringBuilder();

        if (headers.get("content-length") == null) {
            response = createHttpError(400, "Bad Request", "Missing Content-Length header\r\n");
        }

        // retrieve the filename the client wants to write to
        // todo: handle parameters that specify if the client wants the file to be overwritten or not
        String filepath = directoryPath + "/" + headers.get("httpUri");
        boolean valid = isFilepathValid(filepath);
        if (!valid) {
            response = createHttpError(500, "Internal Server Error", "Invalid filepath\r\n");
            return response;
        }
        File file = new File(filepath);

        if (!file.exists()) {
            try {
                boolean success = file.createNewFile();
                if (!success) {
                    response = createHttpError(500, "Internal Server Error", "Server could not create new file\r\n");
                    return response;
                }
            } catch (IOException e) {
                System.out.println(e.getMessage());
                response = createHttpError(500, "Internal Server Error", "Server could not create new file\r\n");
                return response;
            }
        }

        try {
            PrintWriter pw = new PrintWriter(new FileOutputStream(file));
            pw.println(headers.get("requestBody"));
            pw.flush();
        } catch (IOException e) {
            response = createHttpError(500, "Internal Server Error", "Server could not write to file\r\n");
            return response;
        }

        String body = "Successfully written to file\n";
        response.append("HTTP/1.0 200 OK\n");
        response.append("Content-Type: text/html\n");
        response.append("Content-Length: ").append(body.length()).append("\n\n");
        response.append(body).append("\r\n");
        return response;
    }

    public static StringBuilder createHttpError(int statusCode, String statusCodeMessage, String errorBodyMessage) {
        StringBuilder response = new StringBuilder();
        response.append("HTTP/1.0 ").append(statusCode).append(" ").append(statusCodeMessage).append("\nContent-Type: text/html\n")
                .append("Content-Length: ").append(errorBodyMessage.length()).append("\n\n").append(errorBodyMessage);
        return response;
    }

    public static HashMap<String, String> receiveRequest(List<String> httpMessage) throws NoSuchElementException, IOException {
        // this hashmap will contain all the extracted request headers
        HashMap<String, String> headers = new HashMap<>();

        String httpRequest = String.join("", httpMessage);
        if (verbose) System.out.println("HTTP request: \n" + httpRequest);

        // extract the headers of the http message
        String[] tokens = httpRequest.split("\r\n");
        System.out.println("Tokens: \n" + Arrays.toString(tokens));

        // From the request-line we can extract the method, version and uri of the http request
        String[] requestLineTokens = tokens[0].split(" ");
        headers.put("httpMethod", requestLineTokens[0]);
        headers.put("httpUri", requestLineTokens[1].replace("http://", "")
                .replace("https://", "").replaceAll("^(.*?)(/|$)", ""));
        headers.put("httpVersion", requestLineTokens[2].split("/")[1]);

        int startOfRequestBodyIndex = -1;
        for (int i = 1; i < tokens.length; i++) {
            if (tokens[i].isEmpty() || tokens[i].isBlank()) {
                // At this point, the subsequent portion of the tokens is the request body
                startOfRequestBodyIndex = i + 1;
            } else {
                String[] header = tokens[i].split(":");
                if (header.length > 1) headers.put(header[0].trim().toLowerCase(), header[1].trim());
            }
        }

        if (headers.get("httpMethod").equalsIgnoreCase("post") && headers.get("content-length") != null && startOfRequestBodyIndex != -1) {
            int contentLength = Integer.parseInt(headers.get("content-length"));
            StringBuilder postRequestBody = new StringBuilder();

            if (verbose) System.out.println("Parsing request body with content-length of " + contentLength);

            postRequestBody.append(tokens[tokens.length-1]);
            headers.put("requestBody", String.valueOf(postRequestBody));
        }

        if (verbose) {
            System.out.println("\nRaw http request: " + httpRequest);
            System.out.println("\nParsed request headers: " + headers);
        }
        return headers;
    }

    public static StringBuilder sendResponse(HashMap<String, String> headers) {
        StringBuilder response = new StringBuilder();

        if (headers.get("httpMethod").equalsIgnoreCase("get")) {
            response = handleGetRequest(headers);
        } else if (headers.get("httpMethod").equalsIgnoreCase("post")) {
            response = handlePostRequest(headers);
        }

        if (verbose) System.out.println("Http server response: \n\n" + response);
        return response;
    }

    public static void main(String[] args) {

        int portNumber = 8080;
        int routerPort = -1;
        String routerHost = null;

        Options options = new Options();

        options.addOption("v", false, "Prints debugging messages");
        options.addOption("p", true, "Specifies the port number that the server will listen and serve at. Default is 8080.");
        options.addOption("d", true, "Specifies the directory that the server will use to read/write\n" +
                "requested files. Default is the current directory when launching the application.");
        options.addOption(null, "router-port", true, "router port \t Specify the port on which the router is running.");
        options.addOption(null, "router-host", true, "router hostname \t Specify the hostname (IP address or localhost) of the router.");

        CommandLineParser parser = new DefaultParser();
        CommandLine cmd = null;

        try {
            cmd = parser.parse(options, args);
        } catch (ParseException e) {
            System.out.println("Could not parse command line arguments...");
            System.exit(1);
        }

        if (args.length > 0 && args[0].equalsIgnoreCase("help")) {
            printHttpfsHelp();
            System.exit(0);
        }
        if (!cmd.hasOption("--router-port")) {
            System.out.println("--router-port argument must be specified");
            printHttpfsHelp();
            System.exit(0);
        }
        if (!cmd.hasOption("--router-host")) {
            System.out.println("--router-host argument must be specified");
            printHttpfsHelp();
            System.exit(0);
        }

        if (cmd.hasOption("v")) {
            verbose = true;
            System.out.println("Setting verbose option...");
        }
        if (cmd.hasOption("d")) {
            directoryPath = cmd.getOptionValue("d");
        }
        if (cmd.hasOption("p")) {
            portNumber = Integer.parseInt(cmd.getOptionValue("p"));
        }
        if (verbose) {
            System.out.println("Server current working directory: " + directoryPath);
        }

        // parse router & server hostnames and port numbers
        routerPort = Integer.parseInt(cmd.getOptionValue("--router-port"));
        System.out.println("Router port number: " + routerPort);

        routerHost = cmd.getOptionValue("--router-host");
        System.out.println("Router hostname: " + routerHost);

        SocketAddress routerAddress = new InetSocketAddress(routerHost, routerPort);

        // ========================= Interact with the client socket ==============================
        DatagramChannel channel = null;
        try {
            channel = DatagramChannel.open();
            channel.bind(new InetSocketAddress(portNumber)); // make the server listen on the specified port (not an ephemeral one)
            if (verbose) System.out.println("Server listening at " + channel.getLocalAddress());
        } catch (IOException exception) {
            System.out.println("Error creating a datagram channel for server...");
            System.exit(0);
        }

        List<String> httpMessage = new ArrayList<>();
        ByteBuffer buffer = ByteBuffer.allocate(Packet.MAX_LEN).order(ByteOrder.BIG_ENDIAN);
        HashMap<String, String> headers;
        try {
            while (true) {

                buffer.clear();
                channel.receive(buffer);

                // Parse a packet from the received raw data.
                buffer.flip();
                Packet packet = Packet.fromBuffer(buffer);
                System.out.println("Received packet from client: " + packet);
                int packetType = packet.getType();
                long sequenceNumber = packet.getSequenceNumber();
                InetAddress peerAddress = packet.getPeerAddress();
                int peerPort = packet.getPeerPort();

                if (packetType != 2) {
                    // send back an ACK packet with no payload only if the packet is not a SYN packet
                    Packet ack = new Packet(1, sequenceNumber, peerAddress, peerPort, new byte[0]);
                    System.out.println("Sending ACK packet...");
                    channel.send(ack.toBufferArray(), routerAddress);
                }

                if (packetType == 2) {
                    // connection request from a client
                    // send a SYN-ACK datagram back
                    Packet synAck = new Packet(3, sequenceNumber, peerAddress, peerPort, new byte[0]);
                    System.out.println("Connection request from client...");
                    System.out.println("Sending SYN-ACK to client...");
                    channel.send(synAck.toBufferArray(), routerAddress);
                }

                if (packetType == 0) {
                    String payload = new String(packet.getPayload(), UTF_8);
                    httpMessage.add(payload);
                    System.out.println(packet);
                    buffer.flip();

                    if (payload.endsWith("\r\n")) {
                        System.out.println("END OF PACKET!");
                        System.out.println("Data: " + httpMessage);
                        headers = receiveRequest(httpMessage);
                        StringBuilder responseToSend = sendResponse(headers);
                        List<Packet> packetsToSend = Packet.splitMessageIntoPackets(responseToSend, new InetSocketAddress(peerAddress, peerPort));

                        // Switch channel to non-blocking mode since we want to receive ACKs from the client
                        channel.configureBlocking(false);
                        Selector selector = Selector.open();
                        SelectionKey key = channel.register(selector, SelectionKey.OP_READ);

                        System.out.println("Sending http response to client...");
                        for (Packet p: packetsToSend) {
                            try {
                                System.out.println("Sending packet to client: " + p);
                                channel.send(p.toBufferArray(), routerAddress);
                                // Wait for client ACK
                                while(true) {
                                    selector.select(TIMEOUT);
                                    Set<SelectionKey> keys = selector.selectedKeys();
                                    if (keys.isEmpty()) {
                                        System.out.println("Timeout on datagram, sending datagram again...");
                                        channel.send(p.toBufferArray(), routerAddress);
                                    } else {
                                        System.out.println("Received ACK from client for packet " + p);
                                        break;
                                    }
                                    keys.clear();
                                }
                            } catch (IOException exception) {
                                System.out.println("Error sending datagram packet to socket...");
                                System.out.println(exception.getMessage());
                                System.exit(0);
                            }
                        }
                        key.cancel();
                        channel.configureBlocking(true); // Server will wait for new client connections
                        httpMessage.clear();
                    }
                }
            }
        } catch (NoSuchElementException | IOException e) {
            System.out.println(e.getMessage());
            System.out.println("Client has disconnected...");
        }
    }
}
