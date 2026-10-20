package com.himanshu.vulnscan.check.net;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;

/**
 * Test fixture: answers an X.224 connection request with a canned response.
 */
public final class FakeRdpServer implements AutoCloseable {

    public enum Mode {
        /** Accepts standard RDP security (selectedProtocol = 0). */
        STANDARD_RDP,
        /** Requires NLA / CredSSP (selectedProtocol = 2). */
        NLA,
        /** Old server: connection confirm without a negotiation response. */
        NO_NEGOTIATION,
        /** Rejects the connection. */
        DISCONNECT
    }

    private final ServerSocket serverSocket;
    private final Thread thread;
    private final Mode mode;

    private FakeRdpServer(Mode mode) throws IOException {
        this.mode = mode;
        this.serverSocket = new ServerSocket(0, 8, InetAddress.getLoopbackAddress());
        this.thread = new Thread(this::serve, "fake-rdp");
        this.thread.setDaemon(true);
        this.thread.start();
    }

    public static FakeRdpServer start(Mode mode) throws IOException {
        return new FakeRdpServer(mode);
    }

    public int port() {
        return serverSocket.getLocalPort();
    }

    private void serve() {
        while (!serverSocket.isClosed()) {
            try (Socket socket = serverSocket.accept()) {
                socket.setSoTimeout(5000);
                InputStream in = socket.getInputStream();
                byte[] header = readFully(in, 4);
                if (header == null) {
                    continue;
                }
                int length = ((header[2] & 0xFF) << 8) | (header[3] & 0xFF);
                if (length < 7 || length > 4096 || readFully(in, length - 4) == null) {
                    continue;
                }
                OutputStream out = socket.getOutputStream();
                out.write(response());
                out.flush();
            } catch (IOException e) {
                if (serverSocket.isClosed()) {
                    return;
                }
            }
        }
    }

    private byte[] response() {
        return switch (mode) {
            case STANDARD_RDP -> connectionConfirm(0);
            case NLA -> connectionConfirm(2);
            case NO_NEGOTIATION -> new byte[]{
                    0x03, 0x00, 0x00, 0x0B,
                    0x06, (byte) 0xD0,
                    0x00, 0x00, 0x00, 0x00, 0x00
            };
            case DISCONNECT -> new byte[]{
                    0x03, 0x00, 0x00, 0x0B,
                    0x06, (byte) 0x80,
                    0x00, 0x00, 0x00, 0x00, 0x00
            };
        };
    }

    private static byte[] connectionConfirm(int selectedProtocol) {
        return new byte[]{
                0x03, 0x00, 0x00, 0x13,
                0x0E, (byte) 0xD0,
                0x00, 0x00, 0x00, 0x00, 0x00,
                0x02, 0x00, 0x08, 0x00,
                (byte) (selectedProtocol & 0xFF),
                (byte) ((selectedProtocol >>> 8) & 0xFF),
                (byte) ((selectedProtocol >>> 16) & 0xFF),
                (byte) ((selectedProtocol >>> 24) & 0xFF)
        };
    }

    private static byte[] readFully(InputStream in, int length) throws IOException {
        byte[] buffer = new byte[length];
        int read = 0;
        while (read < length) {
            int next = in.read(buffer, read, length - read);
            if (next == -1) {
                return null;
            }
            read += next;
        }
        return buffer;
    }

    @Override
    public void close() throws IOException {
        serverSocket.close();
        thread.interrupt();
    }
}
