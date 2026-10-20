package com.himanshu.vulnscan.check.builtin;

import com.himanshu.vulnscan.check.VulnerabilityCheck;
import com.himanshu.vulnscan.check.net.SshProbe;
import com.himanshu.vulnscan.model.Finding;
import com.himanshu.vulnscan.model.ServiceFingerprint;

import java.util.List;
import java.util.Optional;

public final class SshWeakAlgoCheck implements VulnerabilityCheck {

    private static final int TIMEOUT_MS = 3000;

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
        if (!"ssh".equals(fp.getProtocol()) || fp.getTarget() == null || fp.getTarget().isBlank()) {
            return Optional.empty();
        }

        return SshProbe.query(fp.getTarget(), fp.getPort(), TIMEOUT_MS)
                .map(SshProbe::weakAlgorithms)
                .filter(weak -> !weak.isEmpty())
                .map(weak -> Finding.fromCheck(
                        metadata(),
                        "Weak algorithms offered: " + String.join(", ", weak),
                        "The server negotiates legacy " + describe(weak)
                                + ". Restrict KexAlgorithms, Ciphers, MACs and HostKeyAlgorithms"
                                + " to modern sets (e.g. curve25519-sha256, chacha20-poly1305,"
                                + " hmac-sha2-256, ssh-ed25519)."));
    }

    private static String describe(List<String> weak) {
        boolean kex = weak.stream().anyMatch(a -> a.startsWith("diffie-hellman") || a.startsWith("gss-"));
        boolean hostKey = weak.stream().anyMatch(a -> a.startsWith("ssh-"));
        boolean cipher = weak.stream().anyMatch(a -> a.endsWith("-cbc") || a.startsWith("arcfour"));
        boolean mac = weak.stream().anyMatch(a -> a.startsWith("hmac-") || a.startsWith("umac-"));

        StringBuilder description = new StringBuilder();
        if (kex) {
            description.append("key exchange");
        }
        if (hostKey) {
            description.append(description.isEmpty() ? "" : ", ").append("host key");
        }
        if (cipher) {
            description.append(description.isEmpty() ? "" : ", ").append("cipher");
        }
        if (mac) {
            description.append(description.isEmpty() ? "" : ", ").append("MAC");
        }
        return description.isEmpty() ? "cryptographic" : description.toString();
    }
}
