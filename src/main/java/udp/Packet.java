package udp;

import java.io.IOException;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

// Packet represents a simulated network datagram packet
public class Packet {

    public static final int MIN_LEN = 11;
    public static final int MAX_LEN = 11 + 1024;

    private final int type; // type of the packet, which can be Data (0), ACK (1), SYN (2), SYN-ACK (3), NAK (4)
    private final long sequenceNumber; // unsigned big endian
    private final InetAddress peerAddress;
    private final int peerPort;
    private final byte[] payload; // maximum length of 1013 bytes

    public Packet(int type, long sequenceNumber, InetAddress peerAddress, int peerPort, byte[] payload) {
        this.type = type;
        this.sequenceNumber = sequenceNumber;
        this.peerAddress = peerAddress;
        this.peerPort = peerPort;
        this.payload = payload;
    }

    public byte[] getPayload() {
        return this.payload;
    }

    public long getSequenceNumber() {
        return this.sequenceNumber;
    }

    public InetAddress getPeerAddress() {
        return this.peerAddress;
    }

    public int getPeerPort() {
        return this.peerPort;
    }

    public int getType() {
        return this.type;
    }

    public ByteBuffer toBufferArray() {
        ByteBuffer buffer = ByteBuffer.allocate(MAX_LEN).order(ByteOrder.BIG_ENDIAN);
        buffer.put((byte) type);
        buffer.putInt((int) sequenceNumber);
        buffer.put(peerAddress.getAddress());
        buffer.putShort((short) peerPort);
        buffer.put(payload);
        buffer.flip(); // stop put operations and get ready for get operations
        return buffer;
    }

    public static Packet fromBuffer(ByteBuffer buffer) throws IOException {

        if (buffer.limit() < MIN_LEN || buffer.limit() > MAX_LEN) {
            System.out.println("Buffer length: " + buffer.limit());
            throw new IOException("Invalid buffer length");
        }

        int type = buffer.get();
        long sequenceNum = buffer.getInt(); // read 4 bytes to get the sequence number

        byte[] host = new byte[]{buffer.get(), buffer.get(), buffer.get(), buffer.get()}; // read 4 bytes to get the peer IP address bytes
        InetAddress peerAddress = Inet4Address.getByAddress(host);

        int peerPort = Short.toUnsignedInt(buffer.getShort());
        byte[] payload = new byte[buffer.remaining()];
        buffer.get(payload);

        return new Packet(type, sequenceNum, peerAddress, peerPort, payload);
    }

    public static List<Packet> splitMessageIntoPackets(StringBuilder httpMessage, InetSocketAddress serverAddress) {
        // convert the http packet into a sequence of bytes
        byte[] bytes = httpMessage.toString().getBytes();
        int payloadLength = bytes.length;
        int payloadStartRange = 0;
        int payloadEndRange = 1013;
        List<Packet> packetsToSend = new ArrayList<>();

        // Make udp datagrams from this sequence of bytes
        // start with a sequence number of 3 (3-way handshake took sequence numbers 1 and 2) which will be incremented as communication goes on
        long sequenceNumber = 3;
        int nbrOfPackets = (int) Math.ceil((float) payloadLength / Packet.MAX_LEN);
        for (int i = 0; i < nbrOfPackets; i++) {
            Packet p = new Packet(0, sequenceNumber, serverAddress.getAddress(), serverAddress.getPort(),
                    Arrays.copyOfRange(bytes, payloadStartRange, Math.min(payloadLength, payloadEndRange)));
            packetsToSend.add(p);
            sequenceNumber++;
            payloadStartRange = payloadEndRange;
            payloadEndRange = payloadEndRange + 1013;
            if (payloadEndRange > payloadLength) payloadEndRange = payloadLength;
        }
        return packetsToSend;
    }

    @Override
    public String toString() {
        String packetType = "";
        if (type == 0) packetType = "DATA";
        else if (type == 1) packetType = "ACK";
        else if (type == 2) packetType = "SYN";
        else if (type == 3) packetType = "SYN-ACK";
        else if (type == 4) packetType = "NACK";
        return String.format("Datagram #%d type=%d (%s) peer=%s:%d, size=%d", sequenceNumber, type, packetType, peerAddress, peerPort, payload.length);
    }

}
