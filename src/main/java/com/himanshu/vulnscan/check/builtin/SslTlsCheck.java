package com.himanshu.vulnscan.check.builtin;

import com.himanshu.vulnscan.check.VulnerabilityCheck;
import com.himanshu.vulnscan.check.net.TlsProbe;
import com.himanshu.vulnscan.model.Finding;
import com.himanshu.vulnscan.model.ServiceFingerprint;

import java.util.List;
import java.util.Optional;

public final class SslTlsCheck implements VulnerabilityCheck {

    private static final int TIMEOUT_MS = 3000;

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
        if (!"http".equals(fp.getProtocol()) || fp.getTarget() == null || fp.getTarget().isBlank()) {
            return Optional.empty();
        }

        Optional<TlsProbe.ServerHello> legacy =
                TlsProbe.probeLegacy(fp.getTarget(), fp.getPort(), TIMEOUT_MS);
        if (legacy.isPresent() && TlsProbe.isWeakProtocol(legacy.get().protocolVersion())) {
            TlsProbe.ServerHello hello = legacy.get();
            return Optional.of(Finding.fromCheck(
                    metadata(),
                    hello.protocolName() + " accepted (" + hello.cipherName() + ")",
                    "The endpoint negotiated a deprecated TLS version. Disable TLS 1.0/1.1"
                            + " in the server configuration and require TLS 1.2 or newer"
                            + " (TLS 1.3 preferred)."));
        }

        Optional<TlsProbe.ServerHello> weakCipher =
                TlsProbe.probeWeakCiphers(fp.getTarget(), fp.getPort(), TIMEOUT_MS);
        if (weakCipher.isPresent() && TlsProbe.isWeakCipher(weakCipher.get().cipherSuite())) {
            TlsProbe.ServerHello hello = weakCipher.get();
            return Optional.of(Finding.fromCheck(
                    metadata(),
                    "Legacy cipher accepted over " + hello.protocolName() + ": " + hello.cipherName(),
                    "The endpoint accepts CBC/RC4/3DES cipher suites. Restrict the cipher"
                            + " list to AEAD suites (AES-GCM, ChaCha20-Poly1305) with"
                            + " forward secrecy."));
        }

        return Optional.empty();
    }
}
