package com.himanshu.vulnscan.check.builtin;

import com.himanshu.vulnscan.check.VulnerabilityCheck;
import com.himanshu.vulnscan.model.Finding;
import com.himanshu.vulnscan.model.ServiceFingerprint;

import java.util.List;
import java.util.Optional;

public final class Log4ShellCheck implements VulnerabilityCheck {

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
        return Optional.empty();
    }
}
