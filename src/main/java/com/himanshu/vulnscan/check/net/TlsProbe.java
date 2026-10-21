package com.himanshu.vulnscan.check.net;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * TLS fingerprinting without completing a handshake.
 *
 * <p>JSSE disables TLS 1.0/1.1 and legacy cipher suites by default, which
 * makes it impossible to ask a server whether it still accepts them. This
 * probe therefore writes a minimal ClientHello and reads only the ServerHello:
 * enough to learn the selected protocol version and cipher suite, with no key
 * exchange, no certificate validation and no application data.</p>
 */
public final class TlsProbe {

    private static final int TLS10 = 0x0301;
    private static final int TLS11 = 0x0302;
    private static final int TLS12 = 0x0303;

    private static final SecureRandom RANDOM = new SecureRandom();

    private static final int RECORD_HANDSHAKE = 22;
    private static final int RECORD_ALERT = 21;
    private static final int EXT_SUPPORTED_VERSIONS = 0x002B;

    private static final List<Integer> WEAK_CIPHERS = List.of(
            0x000A, // TLS_RSA_WITH_3DES_EDE_CBC_SHA
            0x0009, // TLS_RSA_WITH_DES_CBC_SHA
            0x0005, // TLS_RSA_WITH_RC4_128_SHA
            0x0004, // TLS_RSA_WITH_RC4_128_MD5
            0x002F, // TLS_RSA_WITH_AES_128_CBC_SHA
            0x0035, // TLS_RSA_WITH_AES_256_CBC_SHA
            0xC013, // TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
            0xC014  // TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
    );

    private static final Map<Integer, String> CIPHER_NAMES = cipherNames();

    private TlsProbe() {
    }

    public record ServerHello(int protocolVersion, int cipherSuite) {
        public String protocolName() {
            return versionName(protocolVersion);
        }

        public String cipherName() {
            return CIPHER_NAMES.getOrDefault(cipherSuite, String.format("0x%04X", cipherSuite));
        }
    }

    /**
     * Offers only TLS 1.1 (and older cipher suites). A ServerHello means the
     * server still negotiates the deprecated protocol.
     */
    public static Optional<ServerHello> probeLegacy(String host, int port, int timeoutMs) {
        return probe(host, port, TLS11, WEAK_CIPHERS, timeoutMs);
    }

    /**
     * Offers TLS 1.2 with only legacy cipher suites. A ServerHello means the
     * server accepts weak ciphers even though the protocol itself is current.
     */
    public static Optional<ServerHello> probeWeakCiphers(String host, int port, int timeoutMs) {
        return probe(host, port, TLS12, WEAK_CIPHERS, timeoutMs);
    }

    public static boolean isWeakProtocol(int version) {
        return version < TLS12;
    }

    public static boolean isWeakCipher(int cipherSuite) {
        return WEAK_CIPHERS.contains(cipherSuite);
    }

    public static String versionName(int version) {
        return switch (version) {
            case 0x0300 -> "SSL 3.0";
            case TLS10 -> "TLS 1.0";
            case TLS11 -> "TLS 1.1";
            case TLS12 -> "TLS 1.2";
            case 0x0304 -> "TLS 1.3";
            default -> String.format("0x%04X", version);
        };
    }

    private static Optional<ServerHello> probe(String host, int port, int maxVersion,
                                               List<Integer> cipherSuites, int timeoutMs) {
        if (host == null || host.isBlank()) {
            return Optional.empty();
        }

        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(host, port), timeoutMs);
            socket.setSoTimeout(timeoutMs);

            OutputStream out = socket.getOutputStream();
            out.write(clientHello(host, maxVersion, cipherSuites));
            out.flush();

            ByteArrayOutputStream handshake = new ByteArrayOutputStream();
            InputStream in = socket.getInputStream();

            for (int record = 0; record < 6; record++) {
                byte[] header = readFully(in, 5);
                if (header.length == 0) {
                    return Optional.empty();
                }
                int type = header[0] & 0xFF;
                int length = ((header[3] & 0xFF) << 8) | (header[4] & 0xFF);
                if (length <= 0 || length > 65_536) {
                    return Optional.empty();
                }
                byte[] payload = readFully(in, length);
                if (payload.length == 0) {
                    return Optional.empty();
                }
                if (type == RECORD_ALERT) {
                    return Optional.empty();
                }
                if (type != RECORD_HANDSHAKE) {
                    continue;
                }
                handshake.write(payload, 0, payload.length);
                Optional<ServerHello> hello = parseServerHello(handshake.toByteArray());
                if (hello.isPresent()) {
                    return hello;
                }
            }
            return Optional.empty();
        } catch (IOException | RuntimeException e) {
            return Optional.empty();
        }
    }

    static Optional<ServerHello> parseServerHello(byte[] handshake) {
        if (handshake == null || handshake.length < 4 + 38 || handshake[0] != 2) {
            return Optional.empty();
        }
        int messageLength = ((handshake[1] & 0xFF) << 16)
                | ((handshake[2] & 0xFF) << 8)
                | (handshake[3] & 0xFF);
        int messageEnd = 4 + messageLength;
        if (messageLength < 38 || messageEnd > handshake.length) {
            return Optional.empty();
        }

        int version = u16(handshake, 4);
        int offset = 4 + 2 + 32;
        int sessionIdLength = handshake[offset] & 0xFF;
        offset += 1 + sessionIdLength;
        if (offset + 3 > messageEnd) {
            return Optional.empty();
        }
        int cipherSuite = u16(handshake, offset);
        offset += 2;
        offset += 1; // compression method

        int selectedVersion = version;
        if (offset + 2 <= messageEnd) {
            int extensionsLength = u16(handshake, offset);
            int extensionsStart = offset + 2;
            int extensionsEnd = Math.min(extensionsStart + extensionsLength, messageEnd);
            int cursor = extensionsStart;
            while (cursor + 4 <= extensionsEnd) {
                int extensionType = u16(handshake, cursor);
                int extensionLength = u16(handshake, cursor + 2);
                int dataStart = cursor + 4;
                if (dataStart + extensionLength > extensionsEnd) {
                    break;
                }
                if (extensionType == EXT_SUPPORTED_VERSIONS && extensionLength == 2) {
                    selectedVersion = u16(handshake, dataStart);
                }
                cursor = dataStart + extensionLength;
            }
        }

        return Optional.of(new ServerHello(selectedVersion, cipherSuite));
    }

    static byte[] clientHello(String host, int maxVersion, List<Integer> cipherSuites) {
        ByteArrayOutputStream extensions = new ByteArrayOutputStream();

        if (!isIpLiteral(host)) {
            byte[] name = host.getBytes(StandardCharsets.US_ASCII);
            ByteArrayOutputStream sni = new ByteArrayOutputStream();
            writeU16(sni, name.length + 3);
            sni.write(0); // host_name
            writeU16(sni, name.length);
            sni.write(name, 0, name.length);
            writeExtension(extensions, 0x0000, sni.toByteArray());
        }

        writeExtension(extensions, 0x000A, new byte[]{
                0x00, 0x04, // list length
                0x00, 0x17, // secp256r1
                0x00, 0x18  // secp384r1
        });
        writeExtension(extensions, 0x000B, new byte[]{0x01, 0x00});
        writeExtension(extensions, 0x000D, new byte[]{
                0x00, 0x08,
                0x04, 0x03, // ecdsa_secp256r1_sha256
                0x04, 0x01, // rsa_pkcs1_sha256
                0x08, 0x04, // rsa_pss_rsae_sha256
                0x02, 0x01  // rsa_pkcs1_sha1
        });

        List<Integer> versions = maxVersion == TLS12 ? List.of(TLS12) : List.of(TLS11, TLS10);
        ByteArrayOutputStream supported = new ByteArrayOutputStream();
        writeU16(supported, versions.size() * 2);
        versions.forEach(version -> writeU16(supported, version));
        writeExtension(extensions, EXT_SUPPORTED_VERSIONS, supported.toByteArray());

        ByteArrayOutputStream body = new ByteArrayOutputStream();
        writeU16(body, maxVersion);
        byte[] random = new byte[32];
        RANDOM.nextBytes(random);
        body.write(random, 0, random.length);
        body.write(0); // empty session id
        writeU16(body, cipherSuites.size() * 2);
        cipherSuites.forEach(suite -> writeU16(body, suite));
        body.write(1);
        body.write(0); // null compression
        byte[] extensionBytes = extensions.toByteArray();
        writeU16(body, extensionBytes.length);
        body.write(extensionBytes, 0, extensionBytes.length);

        byte[] bodyBytes = body.toByteArray();
        ByteArrayOutputStream handshake = new ByteArrayOutputStream();
        handshake.write(1); // ClientHello
        handshake.write((bodyBytes.length >>> 16) & 0xFF);
        handshake.write((bodyBytes.length >>> 8) & 0xFF);
        handshake.write(bodyBytes.length & 0xFF);
        handshake.write(bodyBytes, 0, bodyBytes.length);
        byte[] handshakeBytes = handshake.toByteArray();

        ByteArrayOutputStream record = new ByteArrayOutputStream();
        record.write(RECORD_HANDSHAKE);
        writeU16(record, maxVersion);
        writeU16(record, handshakeBytes.length);
        record.write(handshakeBytes, 0, handshakeBytes.length);
        return record.toByteArray();
    }

    private static void writeExtension(ByteArrayOutputStream out, int type, byte[] data) {
        writeU16(out, type);
        writeU16(out, data.length);
        out.write(data, 0, data.length);
    }

    private static void writeU16(ByteArrayOutputStream out, int value) {
        out.write((value >>> 8) & 0xFF);
        out.write(value & 0xFF);
    }

    private static int u16(byte[] data, int offset) {
        return ((data[offset] & 0xFF) << 8) | (data[offset + 1] & 0xFF);
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

    private static boolean isIpLiteral(String host) {
        return host.matches("[0-9.]+") || host.contains(":");
    }

    private static Map<Integer, String> cipherNames() {
        Map<Integer, String> names = new LinkedHashMap<>();
        names.put(0x000A, "TLS_RSA_WITH_3DES_EDE_CBC_SHA");
        names.put(0x0009, "TLS_RSA_WITH_DES_CBC_SHA");
        names.put(0x0005, "TLS_RSA_WITH_RC4_128_SHA");
        names.put(0x0004, "TLS_RSA_WITH_RC4_128_MD5");
        names.put(0x002F, "TLS_RSA_WITH_AES_128_CBC_SHA");
        names.put(0x0035, "TLS_RSA_WITH_AES_256_CBC_SHA");
        names.put(0xC013, "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA");
        names.put(0xC014, "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA");
        return Map.copyOf(names);
    }
}
