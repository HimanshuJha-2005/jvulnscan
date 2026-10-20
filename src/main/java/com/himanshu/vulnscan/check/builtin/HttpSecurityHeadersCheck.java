package com.himanshu.vulnscan.check.builtin;

import com.himanshu.vulnscan.check.VulnerabilityCheck;
import com.himanshu.vulnscan.check.net.HttpProbe;
import com.himanshu.vulnscan.model.Finding;
import com.himanshu.vulnscan.model.ServiceFingerprint;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;

public final class HttpSecurityHeadersCheck implements VulnerabilityCheck {

    private static final int TIMEOUT_MS = 3000;

    @Override
    public CheckMetadata metadata() {
        return CheckMetadata.builder()
                .id("HTTP-SEC-HEADERS")
                .name("Missing Security Headers")
                .description("HTTP response missing security headers (HSTS, CSP, X-Frame-Options, etc.)")
                .severity(Severity.LOW)
                .cvss(3.7)
                .affectedProducts(List.of("Web applications"))
                .references(List.of("https://owasp.org/www-project-secure-headers/"))
                .tags(List.of("web", "headers", "config"))
                .build();
    }

    @Override
    public Optional<Finding> execute(ServiceFingerprint fp) {
        if (!"http".equals(fp.getProtocol()) || fp.getTarget() == null || fp.getTarget().isBlank()) {
            return Optional.empty();
        }

        return HttpProbe.fetch(fp.getTarget(), fp.getPort(), "/", TIMEOUT_MS)
                .map(response -> {
                    List<String> missing = missingHeaders(response.headers(), "https".equals(response.scheme()));
                    if (missing.isEmpty()) {
                        return null;
                    }
                    String location = response.scheme() + "://" + fp.getTarget() + ":" + fp.getPort() + "/";
                    return Finding.fromCheck(
                            metadata(),
                            "Missing headers at " + location + " (HTTP " + response.statusCode() + "): "
                                    + String.join(", ", missing),
                            "The response lacks " + missing.size() + " recommended security header(s): "
                                    + String.join(", ", missing)
                                    + ". Add them at the reverse proxy or application layer;"
                                    + " use CSP frame-ancestors instead of X-Frame-Options where possible.");
                });
    }

    static List<String> missingHeaders(Map<String, List<String>> headers, boolean https) {
        List<String> missing = new ArrayList<>();

        if (!valueContains(headers, "x-content-type-options", "nosniff")) {
            missing.add("X-Content-Type-Options");
        }

        boolean frameProtection = valueContains(headers, "x-frame-options", "deny")
                || valueContains(headers, "x-frame-options", "sameorigin")
                || valueContains(headers, "content-security-policy", "frame-ancestors");
        if (!frameProtection) {
            missing.add("X-Frame-Options / CSP frame-ancestors");
        }

        if (!hasHeader(headers, "content-security-policy")) {
            missing.add("Content-Security-Policy");
        }
        if (!hasHeader(headers, "referrer-policy")) {
            missing.add("Referrer-Policy");
        }
        if (!hasHeader(headers, "permissions-policy")) {
            missing.add("Permissions-Policy");
        }
        if (https && !hasHeader(headers, "strict-transport-security")) {
            missing.add("Strict-Transport-Security");
        }

        return missing;
    }

    private static boolean hasHeader(Map<String, List<String>> headers, String name) {
        List<String> values = headers.get(name);
        return values != null && values.stream().anyMatch(value -> !value.isBlank());
    }

    private static boolean valueContains(Map<String, List<String>> headers, String name, String needle) {
        List<String> values = headers.get(name);
        if (values == null) {
            return false;
        }
        String normalizedNeedle = needle.toLowerCase(Locale.ROOT);
        return values.stream()
                .anyMatch(value -> value.toLowerCase(Locale.ROOT).contains(normalizedNeedle));
    }
}
