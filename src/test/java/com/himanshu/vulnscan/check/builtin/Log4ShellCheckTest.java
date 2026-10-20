package com.himanshu.vulnscan.check.builtin;

import com.himanshu.vulnscan.check.net.FakeHttpServer;
import com.himanshu.vulnscan.model.Finding;
import com.himanshu.vulnscan.model.ServiceFingerprint;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.util.List;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.*;

@Timeout(30)
class Log4ShellCheckTest {

    private static final Pattern CALLBACK = Pattern.compile("jndi:ldap://([^/}\\s]+)");

    @Test
    void recognizesAffectedVersions() {
        assertEquals(Optional.of("2.14.1"), Log4ShellCheck.vulnerableVersion("X-Powered-By: Log4j-2.14.1"));
        assertEquals(Optional.of("2.0"), Log4ShellCheck.vulnerableVersion("Apache Log4j 2.0-beta9"));
        assertEquals(Optional.of("2.9.1"), Log4ShellCheck.vulnerableVersion("log4j 2.9.1"));

        assertTrue(Log4ShellCheck.vulnerableVersion("Log4j 2.15.0").isEmpty());
        assertTrue(Log4ShellCheck.vulnerableVersion("Log4j 2.17.1").isEmpty());
        assertTrue(Log4ShellCheck.vulnerableVersion("log4j 1.2.17").isEmpty());
        assertTrue(Log4ShellCheck.vulnerableVersion("").isEmpty());
        assertTrue(Log4ShellCheck.vulnerableVersion(null).isEmpty());
    }

    @Test
    void reportsDisclosedVulnerableVersion() throws IOException {
        try (FakeHttpServer server = FakeHttpServer.start(request ->
                "HTTP/1.1 200 OK\r\nX-Powered-By: Log4j-2.14.1\r\nContent-Length: 2\r\n\r\nok")) {

            Optional<Finding> finding = new Log4ShellCheck(false).execute(fingerprint(server.port()));

            assertTrue(finding.isPresent());
            assertTrue(finding.get().getEvidence().contains("2.14.1"));
        }
    }

    @Test
    void reportsLeakedLog4jClasses() throws IOException {
        String body = "<html>java.lang.ClassNotFoundException: org.apache.logging.log4j.core.lookup.JndiLookup</html>";
        try (FakeHttpServer server = FakeHttpServer.start(request ->
                "HTTP/1.1 500 Server Error\r\nContent-Type: text/html\r\nContent-Length: "
                        + body.length() + "\r\n\r\n" + body)) {

            Optional<Finding> finding = new Log4ShellCheck(false).execute(fingerprint(server.port()));

            assertTrue(finding.isPresent());
            assertTrue(finding.get().getEvidence().contains("Log4j component exposed"));
        }
    }

    @Test
    void staysQuietForPatchedOrUnrelatedServices() throws IOException {
        try (FakeHttpServer server = FakeHttpServer.start(request ->
                "HTTP/1.1 200 OK\r\nContent-Length: 18\r\n\r\nnothing to see here")) {

            assertTrue(new Log4ShellCheck(false).execute(fingerprint(server.port())).isEmpty());
        }
    }

    @Test
    void activeProbeConfirmsJndiCallback() throws IOException {
        try (FakeHttpServer server = FakeHttpServer.start(request -> {
            Matcher matcher = CALLBACK.matcher(request);
            if (matcher.find()) {
                triggerCallback(matcher.group(1));
            }
            return "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";
        })) {

            Optional<Finding> finding = new Log4ShellCheck(true).execute(fingerprint(server.port()));

            assertTrue(finding.isPresent());
            String evidence = finding.get().getEvidence();
            assertTrue(evidence.contains("JNDI callback received"));
            assertTrue(evidence.contains("jndi:ldap://"));
        }
    }

    @Test
    void passiveModeDoesNotInjectPayloads() throws IOException {
        try (FakeHttpServer server = FakeHttpServer.start(request ->
                "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")) {

            assertTrue(new Log4ShellCheck(false).execute(fingerprint(server.port())).isEmpty());
            assertFalse(server.requests().stream().anyMatch(request -> request.contains("jndi:ldap")),
                    "passive scan must not inject JNDI payloads");
        }
    }

    @Test
    void ignoresNonWebFingerprints() {
        ServiceFingerprint noTarget = new ServiceFingerprint(
                80, "http", "nginx", "1.24", 0.9, "HTTP/1.1 200 OK", List.of("web"));
        ServiceFingerprint ftp = new ServiceFingerprint(
                "127.0.0.1", 21, "ftp", "vsftpd", "3.0", 0.9, "220 ready", List.of("ftp"));

        assertTrue(new Log4ShellCheck(true).execute(noTarget).isEmpty());
        assertTrue(new Log4ShellCheck(true).execute(ftp).isEmpty());
    }

    private static void triggerCallback(String hostAndPort) {
        int colon = hostAndPort.lastIndexOf(':');
        if (colon <= 0) {
            return;
        }
        String host = hostAndPort.substring(0, colon);
        int port = Integer.parseInt(hostAndPort.substring(colon + 1));
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(host, port), 1000);
        } catch (IOException ignored) {
            // The check's listener may already be gone; the finding would be absent.
        }
    }

    private static ServiceFingerprint fingerprint(int port) {
        return new ServiceFingerprint(
                "127.0.0.1", port, "http", "test", "1.0", 0.9,
                "HTTP/1.1 200 OK", List.of("web"));
    }
}
