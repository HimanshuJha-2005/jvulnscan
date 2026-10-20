package com.himanshu.vulnscan.check.builtin;

import com.himanshu.vulnscan.check.VulnerabilityCheck;
import com.himanshu.vulnscan.check.net.HttpProbe;
import com.himanshu.vulnscan.model.Finding;
import com.himanshu.vulnscan.model.ServiceFingerprint;

import java.util.List;
import java.util.Locale;
import java.util.Optional;

public final class DirectoryListingCheck implements VulnerabilityCheck {

    private static final int TIMEOUT_MS = 3000;

    private static final List<String> MARKERS = List.of(
            "<title>index of /",
            "<h1>index of /",
            "directory listing for",
            "[to parent directory]",
            "index of /</title>"
    );

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
        if (!"http".equals(fp.getProtocol()) || fp.getTarget() == null || fp.getTarget().isBlank()) {
            return Optional.empty();
        }

        return HttpProbe.fetch(fp.getTarget(), fp.getPort(), "/", TIMEOUT_MS)
                .filter(response -> response.statusCode() == 200)
                .flatMap(response -> findMarker(response.body())
                        .map(marker -> Finding.fromCheck(
                                metadata(),
                                "GET / returned \"" + marker + "\" (HTTP 200, "
                                        + response.body().length() + " bytes)",
                                "The web server lists directory contents for the document root."
                                        + " Disable autoindex (nginx), Options -Indexes (Apache)"
                                        + " or directory browsing (IIS) and serve explicit files.")));
    }

    static Optional<String> findMarker(String body) {
        if (body == null || body.isEmpty()) {
            return Optional.empty();
        }
        String normalized = body.toLowerCase(Locale.ROOT);
        for (String marker : MARKERS) {
            int index = normalized.indexOf(marker);
            if (index >= 0) {
                return Optional.of(body.substring(index, index + marker.length()));
            }
        }
        return Optional.empty();
    }
}
