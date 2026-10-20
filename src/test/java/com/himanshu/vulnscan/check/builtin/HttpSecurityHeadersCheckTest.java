package com.himanshu.vulnscan.check.builtin;

import com.himanshu.vulnscan.check.net.FakeHttpServer;
import com.himanshu.vulnscan.model.Finding;
import com.himanshu.vulnscan.model.ServiceFingerprint;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

@Timeout(15)
class HttpSecurityHeadersCheckTest {

    @Test
    void reportsMissingHeaders() throws IOException {
        try (FakeHttpServer server = FakeHttpServer.start(request ->
                "HTTP/1.1 200 OK\r\nServer: test\r\nContent-Length: 5\r\n\r\nhello")) {

            Optional<Finding> finding = new HttpSecurityHeadersCheck().execute(fingerprint(server.port()));

            assertTrue(finding.isPresent());
            String evidence = finding.get().getEvidence();
            assertTrue(evidence.contains("Content-Security-Policy"));
            assertTrue(evidence.contains("Permissions-Policy"));
            assertTrue(evidence.contains("X-Frame-Options"));
            assertFalse(evidence.contains("Strict-Transport-Security"));
        }
    }

    @Test
    void staysQuietWhenAllHeadersArePresent() throws IOException {
        String response = "HTTP/1.1 200 OK\r\n"
                + "X-Content-Type-Options: nosniff\r\n"
                + "X-Frame-Options: DENY\r\n"
                + "Content-Security-Policy: default-src 'self'; frame-ancestors 'none'\r\n"
                + "Referrer-Policy: no-referrer\r\n"
                + "Permissions-Policy: camera=()\r\n"
                + "Content-Length: 2\r\n"
                + "\r\nok";

        try (FakeHttpServer server = FakeHttpServer.start(request -> response)) {
            assertTrue(new HttpSecurityHeadersCheck().execute(fingerprint(server.port())).isEmpty());
        }
    }

    @Test
    void requiresHstsOnlyOverHttps() {
        Map<String, List<String>> headers = Map.of(
                "x-content-type-options", List.of("nosniff"),
                "x-frame-options", List.of("DENY"),
                "content-security-policy", List.of("default-src 'self'"),
                "referrer-policy", List.of("no-referrer"),
                "permissions-policy", List.of("camera=()"));

        assertFalse(HttpSecurityHeadersCheck.missingHeaders(headers, false).contains("Strict-Transport-Security"));
        assertTrue(HttpSecurityHeadersCheck.missingHeaders(headers, true).contains("Strict-Transport-Security"));
    }

    @Test
    void acceptsCspFrameAncestorsInsteadOfXFrameOptions() {
        Map<String, List<String>> headers = Map.of(
                "x-content-type-options", List.of("nosniff"),
                "content-security-policy", List.of("frame-ancestors 'none'"),
                "referrer-policy", List.of("no-referrer"),
                "permissions-policy", List.of("camera=()"),
                "strict-transport-security", List.of("max-age=31536000"));

        assertTrue(HttpSecurityHeadersCheck.missingHeaders(headers, true).isEmpty());
    }

    @Test
    void ignoresNonWebFingerprints() {
        ServiceFingerprint noTarget = new ServiceFingerprint(
                80, "http", "nginx", "1.24", 0.9, "HTTP/1.1 200 OK", List.of("web"));

        assertTrue(new HttpSecurityHeadersCheck().execute(noTarget).isEmpty());
    }

    private static ServiceFingerprint fingerprint(int port) {
        return new ServiceFingerprint(
                "127.0.0.1", port, "http", "test", "1.0", 0.9,
                "HTTP/1.1 200 OK", List.of("web"));
    }
}
