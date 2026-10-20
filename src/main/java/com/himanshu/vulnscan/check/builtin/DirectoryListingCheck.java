package com.himanshu.vulnscan.check.builtin;

import com.himanshu.vulnscan.check.VulnerabilityCheck;
import com.himanshu.vulnscan.model.Finding;
import com.himanshu.vulnscan.model.ServiceFingerprint;

import java.util.List;
import java.util.Optional;

public final class DirectoryListingCheck implements VulnerabilityCheck {

    @Override
    public CheckMetadata metadata() {
        return CheckMetadata.builder()
                .id("DIR-LISTING")
                .name("Directory Listing Enabled")
                .description("Web server exposes directory listing")
                .severity(Severity.LOW)
                .cvss(3.7)
                .affectedProducts(List.of("Apache, Nginx, IIS with autoindex on"))
                .references(List.of("https://owasp.org/www-community/vulnerabilities/Directory_Listing"))
                .tags(List.of("web", "info-leak", "config"))
                .build();
    }

    @Override
    public Optional<Finding> execute(ServiceFingerprint fp) {
        return Optional.empty();
    }
}
