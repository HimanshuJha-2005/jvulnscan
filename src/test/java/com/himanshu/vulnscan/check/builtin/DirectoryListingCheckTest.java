package com.himanshu.vulnscan.check.builtin;

import com.himanshu.vulnscan.check.net.FakeHttpServer;
import com.himanshu.vulnscan.model.Finding;
import com.himanshu.vulnscan.model.ServiceFingerprint;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import java.io.IOException;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

@Timeout(15)
class DirectoryListingCheckTest {

    @Test
    void detectsNginxAutoindex() throws IOException {
        String body = "<html><head><title>Index of /backup/</title></head>"
                + "<body><h1>Index of /backup/</h1><a href=\"../\">../</a></body></html>";
        try (FakeHttpServer server = FakeHttpServer.start(request -> response(200, body))) {

            Optional<Finding> finding = new DirectoryListingCheck().execute(fingerprint(server.port()));

            assertTrue(finding.isPresent());
            assertEquals("DIR-LISTING", finding.get().getCheckId());
            assertTrue(finding.get().getEvidence().contains("Index of /"));
        }
    }

    @Test
    void detectsIisDirectoryBrowsing() {
        Optional<String> marker = DirectoryListingCheck.findMarker(
                "<pre><a href=\"/\">[To Parent Directory]</a><br><br></pre>");

        assertEquals(Optional.of("[To Parent Directory]"), marker);
    }

    @Test
    void ignoresRegularPagesThatMentionDirectories() {
        String body = "<html><body>Welcome. Read the documentation index of /docs in the repo.</body></html>";

        assertTrue(DirectoryListingCheck.findMarker(body).isEmpty());
    }

    @Test
    void ignoresNon200Responses() throws IOException {
        try (FakeHttpServer server = FakeHttpServer.start(request ->
                response(403, "<html><body>Forbidden</body></html>"))) {

            assertTrue(new DirectoryListingCheck().execute(fingerprint(server.port())).isEmpty());
        }
    }

    @Test
    void ignoresEmptyBodiesAndWrongProtocols() {
        assertTrue(DirectoryListingCheck.findMarker("").isEmpty());
        assertTrue(DirectoryListingCheck.findMarker(null).isEmpty());

        ServiceFingerprint ftp = new ServiceFingerprint(
                "127.0.0.1", 21, "ftp", "vsftpd", "3.0", 0.9, "220 ready", List.of("ftp"));
        assertTrue(new DirectoryListingCheck().execute(ftp).isEmpty());
    }

    private static String response(int status, String body) {
        return "HTTP/1.1 " + status + " OK\r\nContent-Type: text/html\r\nContent-Length: "
                + body.length() + "\r\n\r\n" + body;
    }

    private static ServiceFingerprint fingerprint(int port) {
        return new ServiceFingerprint(
                "127.0.0.1", port, "http", "nginx", "1.24", 0.9,
                "HTTP/1.1 200 OK", List.of("web"));
    }
}
