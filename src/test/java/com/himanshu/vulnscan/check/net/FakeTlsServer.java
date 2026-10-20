package com.himanshu.vulnscan.check.net;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

/**
 * Test fixture: answers a raw ClientHello with a canned ServerHello or alert,
 * without doing any cryptography.
 */
public final class FakeTlsServer implements AutoCloseable {

    public enum Mode {
        /** Accepts TLS 1.1 and picks a legacy cipher. */
        LEGACY,
        /** Rejects TLS 1.1 but accepts legacy ciphers over TLS 1.2. */
        MODERN_WEAK_CIPHERS,
        /** Rejects TLS 1.1 and only accepts AEAD ciphers. */
        MODERN,
        /** Not TLS at all. */
        PLAIN
    }

    private static final Set<Integer> WEAK = Set.of(0x000A, 0x0009, 0x0005, 0x0004, 0x002F, 0x0035, 0xC013, 0xC014);
    private static final int[] STRONG = {0xC02F, 0xC030, 0x1301};

    private final ServerSocket serverSocket;
    private final Thread thread;
    private final Mode mode;

    private FakeTlsServer(Mode mode) throws IOException {
        this.mode = mode;
        this.serverSocket = new ServerSocket(0, 8, InetAddress.getLoopbackAddress());
        this.thread = new Thread(this::serve, "fake-tls-" + mode);
        this.thread.setDaemon(true);
        this.thread.start();
    }

    public static FakeTlsServer start(Mode mode) throws IOException {
        return new FakeTlsServer(mode);
    }

    public int port() {
        return serverSocket.getLocalPort();
    }

    private void serve() {
        while (!serverSocket.isClosed()) {
            try (Socket socket = serverSocket.accept()) {
                socket.setSoTimeout(5000);
                if (mode == Mode.PLAIN) {
                    socket.getOutputStream().write("HTTP/1.1 400 Bad Request\r\n\r\n"
                            .getBytes(StandardCharsets.US_ASCII));
                    socket.getOutputStream().flush();
                    continue;
                }
                byte[] hello = readClientHello(socket.getInputStream());
                if (hello == null) {
                    continue;
                }
                byte[] response = respond(hello);
                OutputStream out = socket.getOutputStream();
                out.write(response);
                out.flush();
            } catch (IOException e) {
                if (serverSocket.isClosed()) {
                    return;
                }
            }
        }
    }

    private byte[] respond(byte[] hello) {
        ClientHello parsed = parse(hello);
        if (parsed == null) {
            return alert();
        }

        boolean legacyClient = parsed.maxVersion <= 0x0302;
        if (legacyClient && mode != Mode.LEGACY) {
            return alert();
        }

        Integer chosen = null;
        if (mode == Mode.MODERN) {
            for (int suite : STRONG) {
                if (parsed.cipherSuites.contains(suite)) {
                    chosen = suite;
                    break;
                }
            }
        } else {
            for (Integer suite : parsed.cipherSuites) {
                if (WEAK.contains(suite)) {
                    chosen = suite;
                    break;
                }
            }
        }
        if (chosen == null) {
            return alert();
        }

        int version = legacyClient ? 0x0302 : 0x0303;
        return serverHello(version, chosen);
    }

    private static byte[] serverHello(int version, int cipher) {
        ByteArrayOutputStream body = new ByteArrayOutputStream();
        writeU16(body, version);
        body.write(new byte[32], 0, 32);
        body.write(0); // session id
        writeU16(body, cipher);
        body.write(0); // compression
        writeU16(body, 0); // no extensions

        return record(22, version, handshake(2, body.toByteArray()));
    }

    private static byte[] alert() {
        return new byte[]{0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x28};
    }

    private static byte[] record(int type, int version, byte[] payload) {
        ByteArrayOutputStream record = new ByteArrayOutputStream();
        record.write(type);
        writeU16(record, version);
        writeU16(record, payload.length);
        record.write(payload, 0, payload.length);
        return record.toByteArray();
    }

    private static byte[] handshake(int type, byte[] body) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(type);
        out.write((body.length >>> 16) & 0xFF);
        out.write((body.length >>> 8) & 0xFF);
        out.write(body.length & 0xFF);
        out.write(body, 0, body.length);
        return out.toByteArray();
    }

    private static byte[] readClientHello(InputStream in) throws IOException {
        byte[] header = readFully(in, 5);
        if (header == null) {
            return null;
        }
        int length = u16(header, 3);
        if (length <= 0 || length > 65_536) {
            return null;
        }
        byte[] payload = readFully(in, length);
        if (payload == null) {
            return null;
        }
        byte[] full = new byte[5 + payload.length];
        System.arraycopy(header, 0, full, 0, 5);
        System.arraycopy(payload, 0, full, 5, payload.length);
        return full;
    }

    private record ClientHello(int maxVersion, List<Integer> cipherSuites) {
    }

    private static ClientHello parse(byte[] record) {
        if (record.length < 5 + 4 + 38 || record[0] != 22) {
            return null;
        }
        int offset = 5 + 4;
        int version = u16(record, offset);
        offset += 2 + 32;
        int sessionIdLength = record[offset] & 0xFF;
        offset += 1 + sessionIdLength;
        int cipherLength = u16(record, offset);
        offset += 2;

        List<Integer> suites = new ArrayList<>();
        for (int i = 0; i + 1 < cipherLength; i += 2) {
            suites.add(u16(record, offset + i));
        }
        offset += cipherLength;

        int compressionLength = record[offset] & 0xFF;
        offset += 1 + compressionLength;

        int maxVersion = version;
        if (offset + 2 <= record.length) {
            int extensionsLength = u16(record, offset);
            offset += 2;
            int end = Math.min(offset + extensionsLength, record.length);
            while (offset + 4 <= end) {
                int type = u16(record, offset);
                int length = u16(record, offset + 2);
                offset += 4;
                if (offset + length > end) {
                    break;
                }
                if (type == 0x002B && length >= 2) {
                    int listLength = u16(record, offset);
                    for (int i = 0; i + 1 < listLength; i += 2) {
                        maxVersion = Math.max(maxVersion, u16(record, offset + 2 + i));
                    }
                }
                offset += length;
            }
        }

        return new ClientHello(maxVersion, suites);
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

    private static void writeU16(ByteArrayOutputStream out, int value) {
        out.write((value >>> 8) & 0xFF);
        out.write(value & 0xFF);
    }

    private static int u16(byte[] data, int offset) {
        return ((data[offset] & 0xFF) << 8) | (data[offset + 1] & 0xFF);
    }

    @Override
    public void close() throws IOException {
        serverSocket.close();
        thread.interrupt();
    }
}
