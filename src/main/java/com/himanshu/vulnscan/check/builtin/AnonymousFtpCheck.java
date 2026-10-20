package com.himanshu.vulnscan.check.builtin;

import com.himanshu.vulnscan.check.VulnerabilityCheck;
import com.himanshu.vulnscan.model.Finding;
import com.himanshu.vulnscan.model.ServiceFingerprint;

import java.util.List;
import java.util.Locale;
import java.util.Optional;

public final class AnonymousFtpCheck implements VulnerabilityCheck {

    @Override
    public CheckMetadata metadata() {
        return CheckMetadata.builder()
                .id("ANON-FTP")
                .name("Anonymous FTP Access")
                .description("FTP server allows anonymous login")
                .severity(Severity.MEDIUM)
                .cvss(5.3)
                .affectedProducts(List.of("Any FTP server with anonymous enabled"))
                .references(List.of("https://owasp.org/www-community/vulnerabilities/Anonymous_FTP_Access"))
                .tags(List.of("misconfiguration", "ftp", "info-leak"))
                .build();
    }

    @Override
    public Optional<Finding> execute(ServiceFingerprint fp) {
        if (!"ftp".equals(fp.getProtocol())) return Optional.empty();
        String banner = fp.getRawBanner().toLowerCase(Locale.ROOT);
        if (banner.contains("230") && (banner.contains("anonymous") || banner.contains("guest"))) {
            return Optional.of(Finding.fromCheck(metadata(), banner, "Anonymous FTP login successful"));
        }
        return Optional.empty();
    }
}
