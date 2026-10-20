package com.himanshu.vulnscan.check.builtin;

import com.himanshu.vulnscan.check.VulnerabilityCheck;
import com.himanshu.vulnscan.model.Finding;
import com.himanshu.vulnscan.model.ServiceFingerprint;

import java.util.List;
import java.util.Optional;

public final class MongoOpenCheck implements VulnerabilityCheck {

    @Override
    public CheckMetadata metadata() {
        return CheckMetadata.builder()
                .id("MONGO-OPEN")
                .name("MongoDB Unauthenticated Access")
                .description("MongoDB instance accessible without authentication")
                .severity(Severity.HIGH)
                .cvss(7.5)
                .affectedProducts(List.of("MongoDB with --bind_ip 0.0.0.0 and no auth"))
                .references(List.of("https://www.mongodb.com/docs/manual/security/"))
                .tags(List.of("misconfiguration", "mongodb", "database"))
                .build();
    }

    @Override
    public Optional<Finding> execute(ServiceFingerprint fp) {
        if (!"mongodb".equals(fp.getProtocol())) return Optional.empty();
        return Optional.of(Finding.fromCheck(metadata(), fp.getRawBanner(), "MongoDB may allow unauthenticated access"));
    }
}
