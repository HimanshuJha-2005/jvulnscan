package com.himanshu.vulnscan.check.builtin;

import com.himanshu.vulnscan.check.VulnerabilityCheck;
import com.himanshu.vulnscan.model.Finding;
import com.himanshu.vulnscan.model.ServiceFingerprint;

import java.util.List;
import java.util.Optional;

public final class SshWeakAlgoCheck implements VulnerabilityCheck {

    @Override
    public CheckMetadata metadata() {
        return CheckMetadata.builder()
                .id("SSH-WEAK-ALGO")
                .name("SSH Weak Algorithms")
                .description("SSH server offers weak key exchange, cipher, or MAC algorithms")
                .severity(Severity.MEDIUM)
                .cvss(5.3)
                .affectedProducts(List.of("OpenSSH, Dropbear, other SSH implementations"))
                .references(List.of("https://infosec.mozilla.org/guidelines/openssh"))
                .tags(List.of("crypto", "ssh", "config"))
                .build();
    }

    @Override
    public Optional<Finding> execute(ServiceFingerprint fp) {
        return Optional.empty();
    }
}
