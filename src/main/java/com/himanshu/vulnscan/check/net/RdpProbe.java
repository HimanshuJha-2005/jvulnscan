package com.himanshu.vulnscan.check.net;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.util.Optional;

/**
 * RDP pre-authentication probe (X.224 connection request with an RDP
 * negotiation request). It never authenticates or starts a session.
 */
public final class RdpProbe {

    private static final int TYPE_RDP_NEG_RSP = 0x02;
    private static final int TYPE_RDP_NEG_FAILURE = 0x03;
    private static final int PROTOCOL_RDP = 0;
    private static final int PROTOCOL_HYBRID = 2;
    private static final int PROTOCOL_HYBRID_EX = 8;

    private RdpProbe() {
    }

    /**
     * @param connectionConfirmed server answered with an X.224 connection confirm
     * @param selectedProtocol    negotiated security protocol, or null when the
     *                            server replied without a negotiation response
     */
    public record Negotiation(boolean connectionConfirmed, Integer selectedProtocol) {

        public boolean acceptsStandardRdpSecurity() {
            return connectionConfirmed && (selectedProtocol == null || selectedProtocol == PROTOCOL_RDP);
        }

        public boolean requiresNla() {
            return selectedProtocol != null
                    && (selectedProtocol == PROTOCOL_HYBRID || selectedProtocol == PROTOCOL_HYBRID_EX);
        }
    }

    public static Optional<Negotiation> query(String host, int port, int timeoutMs) {
        if (host == null || host.isBlank()) {
            return Optional.empty();
        }

        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(host, port), timeoutMs);
            socket.setSoTimeout(timeoutMs);

            OutputStream out = socket.getOutputStream();
            out.write(connectionRequest());
            out.flush();

            InputStream in = socket.getInputStream();
            byte[] header = readFully(in, 4);
            if (header.length == 0 || (header[0] & 0xFF) != 3) {
                return Optional.empty();
            }
            int length = ((header[2] & 0xFF) << 8) | (header[3] & 0xFF);
            if (length < 7 || length > 4096) {
                return Optional.empty();
            }
            byte[] rest = readFully(in, length - 4);
            if (rest.length == 0) {
                return Optional.empty();
            }

            byte[] packet = new byte[length];
            System.arraycopy(header, 0, packet, 0, 4);
            System.arraycopy(rest, 0, packet, 4, rest.length);
            return parseResponse(packet);
        } catch (IOException | RuntimeException e) {
            return Optional.empty();
        }
    }

    static byte[] connectionRequest() {
        return new byte[]{
                0x03, 0x00, 0x00, 0x13,       // TPKT header, total length 19
                0x0E,                         // X.224 length
                (byte) 0xE0,                  // connection request
                0x00, 0x00,                   // destination reference
                0x00, 0x00,                   // source reference
                0x00,                         // class 0
                0x01, 0x00, 0x08, 0x00,       // RDP negotiation request, 8 bytes
                0x00, 0x00, 0x00, 0x00        // requestedProtocols = PROTOCOL_RDP
        };
    }

    public static Optional<Negotiation> parseResponse(byte[] packet) {
        if (packet == null || packet.length < 7) {
            return Optional.empty();
        }
        int code = packet[5] & 0xFF;
        if (code == 0x80) {
            return Optional.of(new Negotiation(false, null));
        }
        if (code != 0xD0) {
            return Optional.empty();
        }

        Integer selected = null;
        int offset = 11;
        if (offset + 8 <= packet.length) {
            int type = packet[offset] & 0xFF;
            int length = (packet[offset + 2] & 0xFF) | ((packet[offset + 3] & 0xFF) << 8);
            if (length == 8 && (type == TYPE_RDP_NEG_RSP || type == TYPE_RDP_NEG_FAILURE)) {
                selected = (packet[offset + 4] & 0xFF)
                        | ((packet[offset + 5] & 0xFF) << 8)
                        | ((packet[offset + 6] & 0xFF) << 16)
                        | ((packet[offset + 7] & 0xFF) << 24);
            }
        }
        return Optional.of(new Negotiation(true, selected));
    }

    private static byte[] readFully(InputStream in, int length) throws IOException {
        byte[] buffer = new byte[length];
        int read = 0;
        while (read < length) {
            int next = in.read(buffer, read, length - read);
            if (next == -1) {
                return new byte[0];
            }
            read += next;
        }
        return buffer;
    }
}
