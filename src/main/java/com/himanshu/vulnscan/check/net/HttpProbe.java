package com.himanshu.vulnscan.check.net;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/**
 * Small HTTP/1.1 client used by web checks. It deliberately reads raw
 * responses instead of following redirects, so a scan never leaves the target.
 *
 * <p>TLS certificates are not validated: scanners must be able to inspect
 * hosts with self-signed or expired certificates. Nothing sent over the
 * connection is trusted as configuration.</p>
 */
public final class HttpProbe {

    private static final int MAX_RESPONSE_BYTES = 262_144;
    private static final Set<Integer> TLS_PORTS = Set.of(443, 4443, 8443, 9443);

    private HttpProbe() {
    }

    public record Response(
            String scheme,
            int statusCode,
            Map<String, List<String>> headers,
            String body
    ) {
        public Optional<String> header(String name) {
            List<String> values = headers.get(name.toLowerCase(Locale.ROOT));
            if (values == null || values.isEmpty()) {
                return Optional.empty();
            }
            return Optional.of(String.join(", ", values));
        }
    }

    /**
     * Fetches {@code path} from the target, trying the scheme that is most
     * likely for the port first and falling back to the other one.
     */
    public static Optional<Response> fetch(String host, int port, String path, int timeoutMs) {
        return fetch(host, port, path, Map.of(), timeoutMs);
    }

    /**
     * Fetches {@code path} with additional request headers. The Host header is
     * always derived from the target so a request cannot be redirected at the
     * protocol level.
     */
    public static Optional<Response> fetch(String host, int port, String path,
                                           Map<String, String> headers, int timeoutMs) {
        if (host == null || host.isBlank()) {
            return Optional.empty();
        }

        boolean tlsFirst = TLS_PORTS.contains(port);
        Optional<Response> response = fetch(host, port, path, headers, tlsFirst ? "https" : "http", timeoutMs);
        if (response.isPresent()) {
            return response;
        }
        return fetch(host, port, path, headers, tlsFirst ? "http" : "https", timeoutMs);
    }

    public static boolean isTlsPort(int port) {
        return TLS_PORTS.contains(port);
    }

    private static Optional<Response> fetch(String host, int port, String path, Map<String, String> headers,
                                            String scheme, int timeoutMs) {
        try (Socket raw = new Socket()) {
            raw.connect(new InetSocketAddress(host, port), timeoutMs);
            raw.setSoTimeout(timeoutMs);

            Socket socket = "https".equals(scheme) ? startTls(raw, host, port, timeoutMs) : raw;

            String request = buildRequest(host, port, path, scheme, headers);

            OutputStream out = socket.getOutputStream();
            out.write(request.getBytes(StandardCharsets.US_ASCII));
            out.flush();

            String rawResponse = readAll(socket.getInputStream());
            return parse(scheme, rawResponse);
        } catch (IOException | GeneralSecurityException | RuntimeException e) {
            return Optional.empty();
        }
    }

    private static String buildRequest(String host, int port, String path, String scheme,
                                       Map<String, String> headers) {
        Map<String, String> merged = new LinkedHashMap<>();
        merged.put("User-Agent", "VulnScan/1.0");
        merged.put("Accept", "*/*");
        merged.put("Connection", "close");
        if (headers != null) {
            merged.putAll(headers);
        }
        merged.put("Host", hostHeader(host, port, scheme));

        StringBuilder request = new StringBuilder();
        request.append("GET ").append(path == null || path.isBlank() ? "/" : path).append(" HTTP/1.1\r\n");
        for (Map.Entry<String, String> header : merged.entrySet()) {
            request.append(header.getKey()).append(": ").append(header.getValue()).append("\r\n");
        }
        request.append("\r\n");
        return request.toString();
    }

    private static String readAll(InputStream in) throws IOException {
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        byte[] chunk = new byte[8192];
        try {
            int read;
            while ((read = in.read(chunk)) != -1 && buffer.size() < MAX_RESPONSE_BYTES) {
                buffer.write(chunk, 0, read);
            }
        } catch (SocketTimeoutException e) {
            // Servers that ignore "Connection: close" still replied; parse what arrived.
        }
        return buffer.toString(StandardCharsets.UTF_8);
    }

    static Optional<Response> parse(String scheme, String raw) {
        if (raw == null || raw.isEmpty()) {
            return Optional.empty();
        }

        int separator = raw.indexOf("\r\n\r\n");
        int separatorLength = 4;
        if (separator < 0) {
            separator = raw.indexOf("\n\n");
            separatorLength = 2;
        }
        if (separator <= 0) {
            return Optional.empty();
        }

        String head = raw.substring(0, separator);
        String body = separator + separatorLength <= raw.length()
                ? raw.substring(separator + separatorLength)
                : "";

        String[] lines = head.split("\r?\n");
        int statusCode = parseStatus(lines[0]);
        if (statusCode < 0) {
            return Optional.empty();
        }

        Map<String, List<String>> headers = new LinkedHashMap<>();
        for (int i = 1; i < lines.length; i++) {
            int colon = lines[i].indexOf(':');
            if (colon <= 0) {
                continue;
            }
            String name = lines[i].substring(0, colon).trim().toLowerCase(Locale.ROOT);
            String value = lines[i].substring(colon + 1).trim();
            headers.computeIfAbsent(name, key -> new ArrayList<>()).add(value);
        }

        return Optional.of(new Response(scheme, statusCode, headers, body));
    }

    private static int parseStatus(String statusLine) {
        if (statusLine == null || !statusLine.startsWith("HTTP/")) {
            return -1;
        }
        String[] parts = statusLine.split("\\s+");
        if (parts.length < 2) {
            return -1;
        }
        try {
            return Integer.parseInt(parts[1]);
        } catch (NumberFormatException e) {
            return -1;
        }
    }

    private static String hostHeader(String host, int port, String scheme) {
        String formattedHost = host.contains(":") && !host.startsWith("[") ? "[" + host + "]" : host;
        boolean defaultPort = ("http".equals(scheme) && port == 80)
                || ("https".equals(scheme) && port == 443);
        return defaultPort ? formattedHost : formattedHost + ":" + port;
    }

    private static Socket startTls(Socket raw, String host, int port, int timeoutMs)
            throws GeneralSecurityException, IOException {
        SSLContext context = SSLContext.getInstance("TLS");
        context.init(null, new TrustManager[]{new TrustAllManager()}, new SecureRandom());

        SSLSocketFactory factory = context.getSocketFactory();
        SSLSocket socket = (SSLSocket) factory.createSocket(raw, host, port, true);
        socket.setSoTimeout(timeoutMs);
        socket.setEnabledProtocols(new String[]{"TLSv1.2", "TLSv1.3"});
        socket.startHandshake();
        return socket;
    }

    /**
     * Accepts any certificate. This class only reads HTTP metadata from the
     * target; it never transmits credentials or trusts the peer's identity.
     */
    private static final class TrustAllManager implements X509TrustManager {

        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType) {
            // Scanning self-signed endpoints is intentional.
        }

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType) {
            // Scanning self-signed endpoints is intentional.
        }

        @Override
        public X509Certificate[] getAcceptedIssuers() {
            return new X509Certificate[0];
        }
    }
}
