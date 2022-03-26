package udp;

import java.io.IOException;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

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
            throw new IOException("Invalid length");
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

    @Override
    public String toString() {
        return String.format("#%d peer=%s:%d, size=%d", sequenceNumber, peerAddress, peerPort, payload.length);
    }

}
