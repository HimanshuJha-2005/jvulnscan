package com.himanshu.vulnscan.check.builtin;

import com.himanshu.vulnscan.check.VulnerabilityCheck;
import com.himanshu.vulnscan.model.Finding;
import com.himanshu.vulnscan.model.ServiceFingerprint;

import java.util.List;
import java.util.Optional;

public final class BlueKeepCheck implements VulnerabilityCheck {

    @Override
    public CheckMetadata metadata() {
        return CheckMetadata.builder()
                .id("CVE-2019-0708")
                .name("BlueKeep RDP RCE")
                .description("Pre-authentication remote code execution in RDP")
                .severity(Severity.CRITICAL)
                .cvss(9.8)
                .affectedProducts(List.of("Windows 7, Server 2008 R2, Server 2008"))
                .references(List.of("https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-0708"))
                .tags(List.of("rce", "rdp", "windows", "critical"))
                .build();
    }

    @Override
    public Optional<Finding> execute(ServiceFingerprint fp) {
        return Optional.empty();
    }
}
