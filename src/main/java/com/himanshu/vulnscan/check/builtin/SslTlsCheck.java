package com.himanshu.vulnscan.check.builtin;

import com.himanshu.vulnscan.check.VulnerabilityCheck;
import com.himanshu.vulnscan.model.Finding;
import com.himanshu.vulnscan.model.ServiceFingerprint;

import java.util.List;
import java.util.Optional;

public final class SslTlsCheck implements VulnerabilityCheck {

    @Override
    public CheckMetadata metadata() {
        return CheckMetadata.builder()
                .id("SSL-TLS-WEAK")
                .name("Weak SSL/TLS Configuration")
                .description("Service supports deprecated TLS versions or weak ciphers")
                .severity(Severity.MEDIUM)
                .cvss(5.9)
                .affectedProducts(List.of("Any SSL/TLS service"))
                .references(List.of("https://owasp.org/www-community/vulnerabilities/Weak_SSL_TLS"))
                .tags(List.of("crypto", "tls", "ssl"))
                .build();
    }

    @Override
    public Optional<Finding> execute(ServiceFingerprint fp) {
        return Optional.empty();
    }
}
