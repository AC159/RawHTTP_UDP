package udp;

import org.apache.commons.cli.*;
import org.json.JSONObject;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.HashMap;

public class UDPClient {

    public static void httpcHelp(String helpType) { // helpType can be "get" or "post"
        if (helpType.equalsIgnoreCase("get")) {
            System.out.println("usage: httpc.httpc get [-v] [-h key:value] URL\n" +
                    "Get executes a HTTP GET request for a given URL.\n" +
                    "\t-v \t Prints the detail of the response such as protocol, status and headers.\n" +
                    "\t-h key:value \t Associates headers to HTTP Request with the format 'key:value'.\n"+
                    "\t-p port \t Specify the port on which the client should connect. Default is 80");
        } else if (helpType.equalsIgnoreCase("post")) {
            System.out.println("usage: httpc.httpc post [-v] [-h key:value] [-d inline-data] [-f file] URL\n" +
                    "Post executes a HTTP POST request for a given URL with inline data or from file.\n" +
                    "\t-v \t Prints the detail of the response such as protocol, status and headers.\n" +
                    "\t-h key:value \t Associates headers to HTTP Request with the format 'key:value'.\n" +
                    "\t-d string \t Associates an inline data to the body HTTP POST request.\n" +
                    "\t-f file \t Associates the content of a file to the body HTTP POST request.\n" +
                    "Either [-d] or [-f] can be used but not both.\n" +
                    "\t-p port \t Specify the port on which the client should connect. Default is 80");
        } else {
            System.out.println("httpc.httpc is a curl-like application but supports HTTP protocol only.\n" +
                    "Usage:\n" +
                    "\thttpc.httpc command [arguments]\n" +
                    "The commands are:\n" +
                    "\tget \t executes a HTTP GET request and prints the response.\n" +
                    "\tpost \t executes a HTTP POST request and prints the response.\n" +
                    "\thelp \t prints this screen.\n" +
                    "Use \"httpc.httpc help [command]\" for more information about a command.");
        }
    }

    public static void main(String[] args) {

        if (args.length == 0) {
            httpcHelp("");
            System.exit(0);
        }

        Options options = new Options();
        options.addOption("v", false, "Prints the detail of the response such as protocol, status and headers.");
        options.addOption("h", true, "key:value \t Associates headers to HTTP Request with the format 'key:value'.");
        options.addOption("d", true, "string \t Associates an inline data to the body HTTP POST request.");
        options.addOption("f", true, "file \t Associates the content of a file to the body HTTP POST request.");
        options.addOption("p", true, "port \t Specify the port on which the client should connect.");

        CommandLineParser parser = new DefaultParser();
        CommandLine cmd = null;

        try {
            cmd = parser.parse(options, args);
        } catch (ParseException e) {
            System.out.println("Could not parse command line arguments...");
            System.exit(1);
        }

        boolean verbose = false;
        String[] headers = null;
        String url = args[args.length-1];
        String httpMethod = args[0];
        String data = null;
        int port = 80;
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
        if (cmd.hasOption("p")) {
            port = Integer.parseInt(cmd.getOptionValue("p"));
            System.out.println("Port number for client socket: " + port);
        }

        SocketManager sm = new SocketManager(url, port);

        // Build the query to send to the server
        // Reference: https://developer.mozilla.org/en-US/docs/Web/HTTP/Messages
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
        sm.pw.println(query);
        sm.pw.flush();

        String response;
        BufferedReader reader = new BufferedReader(new InputStreamReader(sm.inputStream));
        HashMap<String, String> responseHeaders = new HashMap<>();
        // parse response headers
        StringBuilder request = new StringBuilder();
        String answer = reader.readLine();

        while (answer.length() > 0) {
            request.append("\n").append(answer);
            answer = reader.readLine();
            String[] header = answer.split(":");
            if (header.length > 1) responseHeaders.put(header[0].trim().toLowerCase(), header[1].trim());
        }

        StringBuilder responseBody = new StringBuilder();
        for (int i = 0; i <= Integer.parseInt(responseHeaders.get("content-length"))-1; i++) {
            answer = String.valueOf((char) reader.read());
            responseBody.append(answer);
        }

        System.out.println(responseBody);

        reader.close();
        sm.closeSocket();
    }

    }
}
