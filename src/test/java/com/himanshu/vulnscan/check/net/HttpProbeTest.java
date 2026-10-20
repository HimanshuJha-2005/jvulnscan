package com.himanshu.vulnscan.check.net;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import java.io.IOException;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

@Timeout(15)
class HttpProbeTest {

    @Test
    void parsesStatusHeadersAndBody() {
        HttpProbe.Response response = HttpProbe.parse("http",
                "HTTP/1.1 404 Not Found\r\n"
                        + "Server: nginx/1.24.0\r\n"
                        + "Content-Type: text/html; charset=utf-8\r\n"
                        + "Set-Cookie: a=1\r\n"
                        + "Set-Cookie: b=2\r\n"
                        + "\r\n"
                        + "<html>missing</html>").orElseThrow();

        assertEquals(404, response.statusCode());
        assertEquals("http", response.scheme());
        assertEquals("nginx/1.24.0", response.header("Server").orElseThrow());
        assertEquals(List.of("a=1", "b=2"), response.headers().get("set-cookie"));
        assertEquals("<html>missing</html>", response.body());
    }

    @Test
    void acceptsLfOnlyResponses() {
        HttpProbe.Response response = HttpProbe.parse("http", "HTTP/1.0 200 OK\nServer: test\n\nbody")
                .orElseThrow();

        assertEquals(200, response.statusCode());
        assertEquals("test", response.header("server").orElseThrow());
        assertEquals("body", response.body());
    }

    @Test
    void rejectsNonHttpPayloads() {
        assertTrue(HttpProbe.parse("http", "").isEmpty());
        assertTrue(HttpProbe.parse("http", "SSH-2.0-OpenSSH_9.6\r\n\r\n").isEmpty());
        assertTrue(HttpProbe.parse("http", "HTTP/1.1\r\n\r\n").isEmpty());
        assertTrue(HttpProbe.parse("http", "HTTP/1.1 OK\r\n\r\n").isEmpty());
    }

    @Test
    void fetchesFromLoopbackServer() throws IOException {
        try (FakeHttpServer server = FakeHttpServer.start(request ->
                "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\n\r\nok")) {

            HttpProbe.Response response = HttpProbe.fetch("127.0.0.1", server.port(), "/health", 2000)
                    .orElseThrow();

            assertEquals(200, response.statusCode());
            assertEquals("ok", response.body());
            assertTrue(server.requests().get(0).startsWith("GET /health HTTP/1.1"));
            assertTrue(server.requests().get(0).contains("Host: 127.0.0.1:" + server.port()));
        }
    }

    @Test
    void returnsEmptyForClosedPort() {
        assertTrue(HttpProbe.fetch("127.0.0.1", 1, "/", 300).isEmpty());
    }

    @Test
    void recognizesDefaultTlsPorts() {
        assertTrue(HttpProbe.isTlsPort(443));
        assertTrue(HttpProbe.isTlsPort(8443));
        assertFalse(HttpProbe.isTlsPort(80));
        assertFalse(HttpProbe.isTlsPort(8080));
    }

    @Test
    void headerLookupIsCaseInsensitive() {
        HttpProbe.Response response = new HttpProbe.Response("http", 200,
                Map.of("content-security-policy", List.of("default-src 'self'")), "");

        assertTrue(response.header("Content-Security-Policy").isPresent());
        assertTrue(response.header("missing").isEmpty());
    }
}
