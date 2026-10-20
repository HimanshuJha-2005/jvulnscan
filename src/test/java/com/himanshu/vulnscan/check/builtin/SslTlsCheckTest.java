package com.himanshu.vulnscan.check.builtin;

import com.himanshu.vulnscan.check.net.FakeTlsServer;
import com.himanshu.vulnscan.check.net.TlsProbe;
import com.himanshu.vulnscan.model.Finding;
import com.himanshu.vulnscan.model.ServiceFingerprint;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import java.io.IOException;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

@Timeout(20)
class SslTlsCheckTest {

    @Test
    void flagsLegacyProtocol() throws IOException {
        try (FakeTlsServer server = FakeTlsServer.start(FakeTlsServer.Mode.LEGACY)) {
            Optional<Finding> finding = new SslTlsCheck().execute(fingerprint(server.port()));

            assertTrue(finding.isPresent());
            assertEquals("SSL-TLS-WEAK", finding.get().getCheckId());
            assertTrue(finding.get().getEvidence().contains("TLS 1.1"));
        }
    }

    @Test
    void flagsLegacyCiphersOverModernProtocol() throws IOException {
        try (FakeTlsServer server = FakeTlsServer.start(FakeTlsServer.Mode.MODERN_WEAK_CIPHERS)) {
            Optional<Finding> finding = new SslTlsCheck().execute(fingerprint(server.port()));

            assertTrue(finding.isPresent());
            assertTrue(finding.get().getEvidence().contains("TLS 1.2"));
            assertTrue(finding.get().getEvidence().contains("CBC"));
        }
    }

    @Test
    void staysQuietForModernTls() throws IOException {
        try (FakeTlsServer server = FakeTlsServer.start(FakeTlsServer.Mode.MODERN)) {
            assertTrue(new SslTlsCheck().execute(fingerprint(server.port())).isEmpty());
        }
    }

    @Test
    void staysQuietForPlainServices() throws IOException {
        try (FakeTlsServer server = FakeTlsServer.start(FakeTlsServer.Mode.PLAIN)) {
            assertTrue(new SslTlsCheck().execute(fingerprint(server.port())).isEmpty());
        }
    }

    @Test
    void classifiesVersionsAndCiphers() {
        assertTrue(TlsProbe.isWeakProtocol(0x0301));
        assertTrue(TlsProbe.isWeakProtocol(0x0302));
        assertFalse(TlsProbe.isWeakProtocol(0x0303));
        assertFalse(TlsProbe.isWeakProtocol(0x0304));

        assertTrue(TlsProbe.isWeakCipher(0x000A));
        assertTrue(TlsProbe.isWeakCipher(0xC013));
        assertFalse(TlsProbe.isWeakCipher(0xC02F));
        assertEquals("TLS 1.1", TlsProbe.versionName(0x0302));
        assertEquals("TLS 1.2", TlsProbe.versionName(0x0303));
    }

    @Test
    void ignoresFingerprintsWithoutTargetOrWrongProtocol() {
        ServiceFingerprint noTarget = new ServiceFingerprint(
                443, "http", "nginx", "1.24", 0.9, "HTTP/1.1 200 OK", List.of("web"));
        ServiceFingerprint ssh = new ServiceFingerprint(
                "127.0.0.1", 22, "ssh", "OpenSSH", "9.6", 0.9, "SSH-2.0-OpenSSH_9.6", List.of("ssh"));

        assertTrue(new SslTlsCheck().execute(noTarget).isEmpty());
        assertTrue(new SslTlsCheck().execute(ssh).isEmpty());
    }

    private static ServiceFingerprint fingerprint(int port) {
        return new ServiceFingerprint(
                "127.0.0.1", port, "http", "test", "1.0", 0.9,
                "HTTP/1.1 200 OK", List.of("web"));
    }
}
