package com.himanshu.vulnscan.check.builtin;

import com.himanshu.vulnscan.check.VulnerabilityCheck;
import com.himanshu.vulnscan.model.Finding;
import com.himanshu.vulnscan.model.ServiceFingerprint;

import java.util.List;
import java.util.Locale;
import java.util.Optional;

public final class RedisUnauthCheck implements VulnerabilityCheck {

    @Override
    public CheckMetadata metadata() {
        return CheckMetadata.builder()
                .id("REDIS-UNAUTH")
                .name("Redis Unauthorized Access")
                .description("Redis instance accessible without authentication")
                .severity(Severity.HIGH)
                .cvss(7.5)
                .affectedProducts(List.of("Redis < 6.0 without requirepass"))
                .references(List.of("https://redis.io/topics/security"))
                .tags(List.of("misconfiguration", "redis", "database"))
                .build();
    }

    @Override
    public Optional<Finding> execute(ServiceFingerprint fp) {
        if (!"redis".equals(fp.getProtocol())) return Optional.empty();
        String banner = fp.getRawBanner().toLowerCase(Locale.ROOT);
        if (banner.contains("redis_version") && !banner.contains("requirepass")) {
            return Optional.of(Finding.fromCheck(metadata(), banner, "Redis allows unauthenticated access"));
        }
        return Optional.empty();
    }
}
