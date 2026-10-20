package com.himanshu.vulnscan.check.builtin;

import com.himanshu.vulnscan.check.CheckRegistry;
import com.himanshu.vulnscan.check.net.FakeFtpServer;
import com.himanshu.vulnscan.model.Finding;
import com.himanshu.vulnscan.model.ServiceFingerprint;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import java.io.IOException;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

@Timeout(20)
class DefaultCredsCheckTest {

    @Test
    void isDisabledUnlessActiveChecksAreEnabled() {
        CheckRegistry passive = new CheckRegistry();
        assertTrue(passive.getCheck("DEFAULT-CREDS").orElseThrow() instanceof DefaultCredsCheck);
        assertFalse(passive.getEnabledChecks().contains(passive.getCheck("DEFAULT-CREDS").orElseThrow()));

        CheckRegistry active = new CheckRegistry(true);
        assertTrue(active.getEnabledChecks().contains(active.getCheck("DEFAULT-CREDS").orElseThrow()));
    }

    @Test
    void reportsAcceptedDefaultPassword() throws IOException {
        try (FakeFtpServer server = FakeFtpServer.start("ftp", "ftp")) {
            Optional<Finding> finding = new DefaultCredsCheck(true).execute(fingerprint(server.port()));

            assertTrue(finding.isPresent());
            assertEquals("DEFAULT-CREDS", finding.get().getCheckId());
            assertTrue(finding.get().getEvidence().contains("ftp"));
            assertFalse(finding.get().getEvidence().contains("password=ftp"));
        }
    }

    @Test
    void triesSeveralDefaultAccounts() throws IOException {
        try (FakeFtpServer server = FakeFtpServer.start("admin", "admin")) {
            assertTrue(new DefaultCredsCheck(true).execute(fingerprint(server.port())).isPresent());
        }
    }

    @Test
    void staysQuietWhenNoDefaultWorks() throws IOException {
        try (FakeFtpServer server = FakeFtpServer.start("realuser", "s3cret")) {
            assertTrue(new DefaultCredsCheck(true).execute(fingerprint(server.port())).isEmpty());
        }
    }

    @Test
    void ignoresNonFtpFingerprints() {
        ServiceFingerprint http = new ServiceFingerprint(
                "127.0.0.1", 80, "http", "nginx", "1.24", 0.9, "HTTP/1.1 200 OK", List.of("web"));

        assertTrue(new DefaultCredsCheck(true).execute(http).isEmpty());
    }

    private static ServiceFingerprint fingerprint(int port) {
        return new ServiceFingerprint(
                "127.0.0.1", port, "ftp", "Fake FTP", "1.0", 0.9,
                "220 Fake FTP ready", List.of("ftp"));
    }
}
