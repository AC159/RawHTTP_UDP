package udp;

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
        buffer.put((byte) sequenceNumber);
        buffer.put(peerAddress.getAddress());
        buffer.put(payload);
        buffer.flip(); // stop put operations and get ready for get operations
        return buffer;
    }

    @Override
    public String toString() {
        return String.format("#%d peer=%s:%d, size=%d", sequenceNumber, peerAddress, peerPort, payload.length);
    }

}
