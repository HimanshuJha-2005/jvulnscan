package com.himanshu.vulnscan.check.builtin;

import com.himanshu.vulnscan.check.VulnerabilityCheck;
import com.himanshu.vulnscan.model.Finding;
import com.himanshu.vulnscan.model.ServiceFingerprint;

import java.util.List;
import java.util.Optional;

public final class DefaultCredsCheck implements VulnerabilityCheck {

    @Override
    public CheckMetadata metadata() {
        return CheckMetadata.builder()
                .id("DEFAULT-CREDS")
                .name("Default Credentials")
                .description("Service uses default/weak credentials")
                .severity(Severity.HIGH)
                .cvss(7.5)
                .affectedProducts(List.of("Various network services"))
                .references(List.of("https://owasp.org/www-community/vulnerabilities/Default_Credentials"))
                .tags(List.of("auth", "default-creds", "brute-force"))
                .build();
    }

    @Override
    public Optional<Finding> execute(ServiceFingerprint fp) {
        return Optional.empty();
    }
}
