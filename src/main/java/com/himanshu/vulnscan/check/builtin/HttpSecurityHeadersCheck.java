package com.himanshu.vulnscan.check.builtin;

import com.himanshu.vulnscan.check.VulnerabilityCheck;
import com.himanshu.vulnscan.model.Finding;
import com.himanshu.vulnscan.model.ServiceFingerprint;

import java.util.List;
import java.util.Optional;

public final class HttpSecurityHeadersCheck implements VulnerabilityCheck {

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
        return Optional.empty();
    }
}
