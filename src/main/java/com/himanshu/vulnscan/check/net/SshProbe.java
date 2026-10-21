package com.himanshu.vulnscan.check.net;

import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.Set;
import java.util.TreeSet;

/**
 * Minimal SSH transport handshake: exchanges identification strings, sends a
 * KEXINIT proposal and parses the server's KEXINIT name-lists.
 *
 * <p>No key exchange is performed, so no cryptography is involved. This is
 * enough to learn which algorithms a server is willing to negotiate.</p>
 */
public final class SshProbe {

    private static final String CLIENT_ID = "SSH-2.0-VulnScan_1.0";
    private static final int MAX_PACKET = 35_000;

    private static final Set<String> WEAK_KEX = Set.of(
            "diffie-hellman-group1-sha1",
            "diffie-hellman-group14-sha1",
            "diffie-hellman-group-exchange-sha1",
            "rsa1024-sha1"
    );

    private static final Set<String> WEAK_HOST_KEY = Set.of(
            "ssh-dss",
            "ssh-rsa"
    );

    private static final Set<String> WEAK_CIPHERS = Set.of(
            "3des-cbc",
            "blowfish-cbc",
            "cast128-cbc",
            "arcfour",
            "arcfour128",
            "arcfour256",
            "none"
    );

    private static final Set<String> WEAK_MACS = Set.of(
            "hmac-md5",
            "hmac-md5-96",
            "hmac-sha1-96",
            "hmac-ripemd160",
            "umac-64",
            "umac-64@openssh.com",
            "none"
    );

    private SshProbe() {
    }

    public record Algorithms(
            List<String> kex,
            List<String> hostKey,
            List<String> ciphers,
            List<String> macs
    ) {
        public Algorithms {
            kex = List.copyOf(kex);
            hostKey = List.copyOf(hostKey);
            ciphers = List.copyOf(ciphers);
            macs = List.copyOf(macs);
        }
    }

    public static Optional<Algorithms> query(String host, int port, int timeoutMs) {
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(host, port), timeoutMs);
            socket.setSoTimeout(timeoutMs);

            InputStream in = socket.getInputStream();
            OutputStream out = socket.getOutputStream();

            String serverId = readIdentification(in);
            if (serverId == null) {
                return Optional.empty();
            }

            out.write((CLIENT_ID + "\r\n").getBytes(StandardCharsets.US_ASCII));
            out.flush();
            writeFully(out, encodeKexInit(
                    List.of("curve25519-sha256", "curve25519-sha256@libssh.org", "diffie-hellman-group14-sha256"),
                    List.of("ssh-ed25519", "rsa-sha2-256"),
                    List.of("aes128-ctr", "aes256-ctr"),
                    List.of("hmac-sha2-256", "hmac-sha2-512")));

            for (int i = 0; i < 5; i++) {
                byte[] payload = readPacket(in);
                if (payload.length == 0) {
                    return Optional.empty();
                }
                if (payload.length > 0 && payload[0] == 20) {
                    return parseKexInit(payload);
                }
            }
            return Optional.empty();
        } catch (IOException e) {
            return Optional.empty();
        }
    }

    /**
     * Parses a KEXINIT payload (message type 20) into the four algorithm lists
     * that matter for grading. Returns empty when the payload is truncated or
     * is not a KEXINIT message.
     */
    public static Optional<Algorithms> parseKexInit(byte[] payload) {
        if (payload == null || payload.length < 17 || payload[0] != 20) {
            return Optional.empty();
        }

        int offset = 17; // message type + 16-byte cookie
        List<List<String>> lists = new ArrayList<>(10);
        for (int i = 0; i < 10; i++) {
            if (offset + 4 > payload.length) {
                return Optional.empty();
            }
            int length = ((payload[offset] & 0xFF) << 24)
                    | ((payload[offset + 1] & 0xFF) << 16)
                    | ((payload[offset + 2] & 0xFF) << 8)
                    | (payload[offset + 3] & 0xFF);
            offset += 4;
            if (length < 0 || offset + length > payload.length) {
                return Optional.empty();
            }
            String raw = new String(payload, offset, length, StandardCharsets.US_ASCII);
            offset += length;
            lists.add(raw.isEmpty() ? List.of() : split(raw));
        }

        List<String> ciphers = new ArrayList<>(lists.get(2));
        ciphers.addAll(lists.get(3));
        List<String> macs = new ArrayList<>(lists.get(4));
        macs.addAll(lists.get(5));

        return Optional.of(new Algorithms(
                lists.get(0), lists.get(1), deduplicate(ciphers), deduplicate(macs)));
    }

    /**
     * Returns the weak algorithms offered by the server, sorted for stable
     * evidence output. Empty means the offered set is acceptable.
     */
    public static List<String> weakAlgorithms(Algorithms algorithms) {
        Set<String> weak = new TreeSet<>(Comparator.naturalOrder());

        for (String kex : algorithms.kex()) {
            if (WEAK_KEX.contains(kex) || kex.startsWith("gss-group1-sha1-")) {
                weak.add(kex);
            }
        }
        for (String hostKey : algorithms.hostKey()) {
            if (WEAK_HOST_KEY.contains(hostKey)) {
                weak.add(hostKey);
            }
        }
        for (String cipher : algorithms.ciphers()) {
            String normalized = cipher.toLowerCase(Locale.ROOT);
            if (WEAK_CIPHERS.contains(normalized) || normalized.endsWith("-cbc")) {
                weak.add(cipher);
            }
        }
        for (String mac : algorithms.macs()) {
            String normalized = mac.toLowerCase(Locale.ROOT);
            if (WEAK_MACS.contains(normalized) || normalized.startsWith("hmac-md5")) {
                weak.add(mac);
            }
        }
        return List.copyOf(weak);
    }

    static byte[] encodeKexInit(List<String> kex, List<String> hostKey,
                                List<String> ciphers, List<String> macs) {
        byte[] body = kexInitPayload(kex, hostKey, ciphers, macs);
        int blockSize = 8;
        int paddingLength = blockSize - ((4 + body.length + 1) % blockSize);
        if (paddingLength < 4) {
            paddingLength += blockSize;
        }

        ByteArrayOutputStream packet = new ByteArrayOutputStream();
        writeInt(packet, body.length + 1 + paddingLength);
        packet.write(paddingLength);
        packet.write(body, 0, body.length);
        for (int i = 0; i < paddingLength; i++) {
            packet.write(0);
        }
        return packet.toByteArray();
    }

    static byte[] kexInitPayload(List<String> kex, List<String> hostKey,
                                 List<String> ciphers, List<String> macs) {
        ByteArrayOutputStream payload = new ByteArrayOutputStream();
        payload.write(20);
        for (int i = 0; i < 16; i++) {
            payload.write(i);
        }
        writeNameList(payload, kex);
        writeNameList(payload, hostKey);
        writeNameList(payload, ciphers); // encryption client-to-server
        writeNameList(payload, ciphers); // encryption server-to-client
        writeNameList(payload, macs);    // MAC client-to-server
        writeNameList(payload, macs);    // MAC server-to-client
        writeNameList(payload, List.of("none")); // compression c2s
        writeNameList(payload, List.of("none")); // compression s2c
        writeNameList(payload, List.of());       // languages c2s
        writeNameList(payload, List.of());       // languages s2c
        payload.write(0); // first_kex_packet_follows
        writeInt(payload, 0); // reserved
        return payload.toByteArray();
    }

    private static void writeNameList(ByteArrayOutputStream out, List<String> names) {
        byte[] value = String.join(",", names).getBytes(StandardCharsets.US_ASCII);
        writeInt(out, value.length);
        out.write(value, 0, value.length);
    }

    private static void writeInt(ByteArrayOutputStream out, int value) {
        out.write((value >>> 24) & 0xFF);
        out.write((value >>> 16) & 0xFF);
        out.write((value >>> 8) & 0xFF);
        out.write(value & 0xFF);
    }

    private static void writeFully(OutputStream out, byte[] data) throws IOException {
        out.write(data);
        out.flush();
    }

    private static List<String> split(String raw) {
        List<String> values = new ArrayList<>();
        for (String part : raw.split(",")) {
            if (!part.isBlank()) {
                values.add(part.trim());
            }
        }
        return values;
    }

    private static List<String> deduplicate(List<String> values) {
        return List.copyOf(new java.util.LinkedHashSet<>(values));
    }

    private static String readIdentification(InputStream in) throws IOException {
        for (int line = 0; line < 10; line++) {
            String value = readLine(in, 255);
            if (value == null) {
                return null;
            }
            if (value.startsWith("SSH-")) {
                return value;
            }
        }
        return null;
    }

    private static String readLine(InputStream in, int maxLength) throws IOException {
        ByteArrayOutputStream line = new ByteArrayOutputStream();
        int next;
        while ((next = in.read()) != -1) {
            if (next == '\n') {
                if (line.size() > 0 && line.toByteArray()[line.size() - 1] == '\r') {
                    byte[] raw = line.toByteArray();
                    return new String(raw, 0, raw.length - 1, StandardCharsets.US_ASCII);
                }
                return line.toString(StandardCharsets.US_ASCII);
            }
            line.write(next);
            if (line.size() > maxLength) {
                return null;
            }
        }
        return null;
    }

    private static byte[] readPacket(InputStream in) throws IOException {
        DataInputStream data = new DataInputStream(in);
        int packetLength;
        try {
            packetLength = data.readInt();
        } catch (IOException e) {
            return new byte[0];
        }
        if (packetLength < 5 || packetLength > MAX_PACKET) {
            return new byte[0];
        }

        byte[] packet = new byte[packetLength];
        try {
            data.readFully(packet);
        } catch (IOException e) {
            return new byte[0];
        }

        int paddingLength = packet[0] & 0xFF;
        int payloadLength = packetLength - paddingLength - 1;
        if (payloadLength <= 0 || payloadLength > packet.length - 1) {
            return new byte[0];
        }
        byte[] payload = new byte[payloadLength];
        System.arraycopy(packet, 1, payload, 0, payloadLength);
        return payload;
    }
}