package com.himanshu.vulnscan.check.net;

import com.himanshu.vulnscan.check.builtin.SshWeakAlgoCheck;
import com.himanshu.vulnscan.model.Finding;
import com.himanshu.vulnscan.model.ServiceFingerprint;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

@Timeout(15)
class SshProbeTest {

    private static final List<String> MODERN_KEX = List.of("curve25519-sha256", "diffie-hellman-group16-sha512");
    private static final List<String> MODERN_HOST_KEY = List.of("ssh-ed25519", "rsa-sha2-256");
    private static final List<String> MODERN_CIPHERS = List.of("chacha20-poly1305@openssh.com", "aes256-gcm@openssh.com");
    private static final List<String> MODERN_MACS = List.of("hmac-sha2-256", "hmac-sha2-512");

    @Test
    void parsesAlgorithmListsFromKexInit() {
        byte[] payload = SshProbe.kexInitPayload(
                List.of("diffie-hellman-group1-sha1", "curve25519-sha256"),
                List.of("ssh-rsa"),
                List.of("3des-cbc", "aes128-ctr"),
                List.of("hmac-md5", "hmac-sha2-256"));

        SshProbe.Algorithms algorithms = SshProbe.parseKexInit(payload).orElseThrow();

        assertEquals(List.of("diffie-hellman-group1-sha1", "curve25519-sha256"), algorithms.kex());
        assertEquals(List.of("ssh-rsa"), algorithms.hostKey());
        assertEquals(List.of("3des-cbc", "aes128-ctr"), algorithms.ciphers());
        assertEquals(List.of("hmac-md5", "hmac-sha2-256"), algorithms.macs());
    }

    @Test
    void rejectsTruncatedPayload() {
        byte[] payload = SshProbe.kexInitPayload(MODERN_KEX, MODERN_HOST_KEY, MODERN_CIPHERS, MODERN_MACS);

        assertTrue(SshProbe.parseKexInit(new byte[]{20, 0, 0}).isEmpty());
        assertTrue(SshProbe.parseKexInit(java.util.Arrays.copyOf(payload, payload.length - 8)).isEmpty());
        assertTrue(SshProbe.parseKexInit(new byte[]{21, 0, 0, 0}).isEmpty());
    }

    @Test
    void flagsLegacyAlgorithms() {
        SshProbe.Algorithms algorithms = new SshProbe.Algorithms(
                List.of("diffie-hellman-group14-sha1"),
                List.of("ssh-dss"),
                List.of("aes128-cbc", "3des-cbc"),
                List.of("hmac-sha1-96"));

        List<String> weak = SshProbe.weakAlgorithms(algorithms);

        assertTrue(weak.contains("diffie-hellman-group14-sha1"));
        assertTrue(weak.contains("ssh-dss"));
        assertTrue(weak.contains("aes128-cbc"));
        assertTrue(weak.contains("3des-cbc"));
        assertTrue(weak.contains("hmac-sha1-96"));
    }

    @Test
    void acceptsModernAlgorithms() {
        assertTrue(SshProbe.weakAlgorithms(new SshProbe.Algorithms(
                MODERN_KEX, MODERN_HOST_KEY, MODERN_CIPHERS, MODERN_MACS)).isEmpty());
    }

    @Test
    void negotiatesWithFakeServerAndReportsFinding() throws IOException {
        try (FakeSshServer server = new FakeSshServer(
                List.of("diffie-hellman-group1-sha1", "curve25519-sha256"),
                List.of("ssh-rsa"),
                List.of("3des-cbc", "aes128-ctr"),
                List.of("hmac-md5"))) {

            ServiceFingerprint fp = fingerprint(server.port());
            Optional<Finding> finding = new SshWeakAlgoCheck().execute(fp);

            assertTrue(finding.isPresent());
            assertEquals("SSH-WEAK-ALGO", finding.get().getCheckId());
            assertTrue(finding.get().getEvidence().contains("diffie-hellman-group1-sha1"));
            assertTrue(finding.get().getEvidence().contains("3des-cbc"));
        }
    }

    @Test
    void staysQuietWhenServerOffersModernAlgorithms() throws IOException {
        try (FakeSshServer server = new FakeSshServer(
                MODERN_KEX, MODERN_HOST_KEY, MODERN_CIPHERS, MODERN_MACS)) {

            assertTrue(new SshWeakAlgoCheck().execute(fingerprint(server.port())).isEmpty());
        }
    }

    @Test
    void skipsFingerprintsWithoutTargetOrWrongProtocol() {
        ServiceFingerprint noTarget = new ServiceFingerprint(
                22, "ssh", "OpenSSH", "9.6", 0.9, "SSH-2.0-OpenSSH_9.6", List.of("ssh"));
        ServiceFingerprint wrongProtocol = new ServiceFingerprint(
                "127.0.0.1", 80, "http", "nginx", "1.0", 0.9, "HTTP/1.1 200 OK", List.of("web"));

        assertTrue(new SshWeakAlgoCheck().execute(noTarget).isEmpty());
        assertTrue(new SshWeakAlgoCheck().execute(wrongProtocol).isEmpty());
    }

    private static ServiceFingerprint fingerprint(int port) {
        return new ServiceFingerprint(
                "127.0.0.1", port, "ssh", "FakeSSH", "1.0", 0.9,
                "SSH-2.0-FakeSSH_1.0", List.of("ssh"));
    }

    private static final class FakeSshServer implements AutoCloseable {

        private final ServerSocket serverSocket;
        private final Thread thread;

        FakeSshServer(List<String> kex, List<String> hostKey,
                      List<String> ciphers, List<String> macs) throws IOException {
            this.serverSocket = new ServerSocket(0, 1, InetAddress.getLoopbackAddress());
            byte[] response = SshProbe.encodeKexInit(kex, hostKey, ciphers, macs);
            this.thread = new Thread(() -> serve(response), "fake-ssh");
            this.thread.setDaemon(true);
            this.thread.start();
        }

        int port() {
            return serverSocket.getLocalPort();
        }

        private void serve(byte[] response) {
            try (Socket socket = serverSocket.accept()) {
                InputStream in = socket.getInputStream();
                OutputStream out = socket.getOutputStream();

                out.write("SSH-2.0-FakeSSH_1.0\r\n".getBytes(StandardCharsets.US_ASCII));
                out.flush();

                readLine(in); // client identification
                readPacket(in); // client KEXINIT

                out.write(response);
                out.flush();

                Thread.sleep(250);
            } catch (IOException e) {
                // The test asserts on the client side; a closed socket is fine.
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }

        private static String readLine(InputStream in) throws IOException {
            StringBuilder line = new StringBuilder();
            int next;
            while ((next = in.read()) != -1) {
                if (next == '\n') {
                    return line.toString();
                }
                line.append((char) next);
            }
            return line.toString();
        }

        private static void readPacket(InputStream in) throws IOException {
            DataInputStream data = new DataInputStream(in);
            int length = data.readInt();
            if (length < 5 || length > 35_000) {
                throw new IOException("unexpected packet length: " + length);
            }
            data.readFully(new byte[length]);
        }

        @Override
        public void close() throws IOException {
            serverSocket.close();
            thread.interrupt();
        }
    }
}
