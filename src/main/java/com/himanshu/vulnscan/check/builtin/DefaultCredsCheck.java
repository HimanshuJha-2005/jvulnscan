package com.himanshu.vulnscan.check.builtin;

import com.himanshu.vulnscan.check.VulnerabilityCheck;
import com.himanshu.vulnscan.check.net.FtpProbe;
import com.himanshu.vulnscan.model.Finding;
import com.himanshu.vulnscan.model.ServiceFingerprint;

import java.util.List;
import java.util.Optional;

/**
 * Opt-in check: it sends login attempts, so it only runs when the operator
 * passes {@code --active} (the registry filters on {@link #isEnabled()}).
 */
public final class DefaultCredsCheck implements VulnerabilityCheck {

    private static final int TIMEOUT_MS = 3000;

    private static final List<Credentials> DEFAULTS = List.of(
            new Credentials("ftp", "ftp"),
            new Credentials("admin", "admin"),
            new Credentials("root", "root"),
            new Credentials("guest", "guest"),
            new Credentials("test", "test")
    );

    private final boolean active;

    public DefaultCredsCheck(boolean active) {
        this.active = active;
    }

    @Override
    public boolean isEnabled() {
        return active;
    }

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
        if (!"ftp".equals(fp.getProtocol()) || fp.getTarget() == null || fp.getTarget().isBlank()) {
            return Optional.empty();
        }

        for (Credentials credentials : DEFAULTS) {
            Optional<String> result = FtpProbe.login(
                    fp.getTarget(), fp.getPort(), credentials.username(), credentials.password(), TIMEOUT_MS);
            if (result.isPresent()) {
                return Optional.of(Finding.fromCheck(
                        metadata(),
                        "FTP default credentials accepted: " + result.get(),
                        "The FTP service accepts a shipped default account. Change the password,"
                                + " disable unused accounts and restrict the service to trusted networks."));
            }
        }
        return Optional.empty();
    }

    private record Credentials(String username, String password) {
    }
}
