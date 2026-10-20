package com.himanshu.vulnscan.scanner;

import com.himanshu.vulnscan.model.PortScanResult;
import com.himanshu.vulnscan.model.ServiceFingerprint;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class ServiceDetector {

    private static final Logger log = LoggerFactory.getLogger(ServiceDetector.class);

    private final List<ServiceProbe> probes = new ArrayList<>();

    public ServiceDetector() {
        registerDefaultProbes();
    }

    public void registerProbe(ServiceProbe probe) {
        probes.add(probe);
        probes.sort(Comparator.comparingInt(ServiceProbe::getPriority).reversed());
    }

    public List<ServiceFingerprint> detect(String target, List<PortScanResult> openPorts) {
        List<ServiceFingerprint> fingerprints = new ArrayList<>();

        for (PortScanResult result : openPorts) {
            if (!result.isOpen() || result.getBanner() == null) {
                continue;
            }

            // matchProbe never returns null (falls back to a generic fingerprint).
            ServiceFingerprint fingerprint = matchProbe(target, result);
            fingerprints.add(fingerprint);
            log.debug("Identified {} on {}:{}", fingerprint.getProduct(), target, result.getPort());
        }

        return fingerprints;
    }

    private ServiceFingerprint matchProbe(String target, PortScanResult result) {
        String banner = result.getBanner();
        int port = result.getPort();

        for (ServiceProbe probe : probes) {
            if (!probe.matchesPort(port)) {
                continue;
            }

            Matcher matcher = probe.getPattern().matcher(banner);
            if (matcher.find()) {
                String product = probe.getProduct();
                String version = extractVersion(matcher, probe.getVersionGroup());
                double confidence = probe.getBaseConfidence();

                if (version != null && !version.isBlank()) {
                    confidence += 0.15;
                }

                List<String> tags = new ArrayList<>(probe.getTags());
                if (probe.isHighValueTarget()) {
                    tags.add("high-value");
                }

                return new ServiceFingerprint(
                        target,
                        port,
                        probe.getProtocol(),
                        product,
                        version,
                        Math.min(confidence, 1.0),
                        banner,
                        tags
                );
            }
        }

        // Generic fallback based on port
        return createGenericFingerprint(target, port, banner);
    }

    private String extractVersion(Matcher matcher, int groupIndex) {
        if (groupIndex <= 0 || groupIndex > matcher.groupCount()) {
            return null;
        }
        String version = matcher.group(groupIndex);
        return version != null ? version.trim() : null;
    }

    private ServiceFingerprint createGenericFingerprint(String target, int port, String banner) {
        String protocol = guessProtocol(port);
        return new ServiceFingerprint(
                target,
                port,
                protocol,
                "unknown",
                null,
                0.1,
                banner,
                List.of("generic")
        );
    }

    private String guessProtocol(int port) {
        return switch (port) {
            case 21, 990 -> "ftp";
            case 22 -> "ssh";
            case 23, 992 -> "telnet";
            case 25, 465, 587 -> "smtp";
            case 53 -> "dns";
            case 80, 443, 8080, 8443, 8000, 8888 -> "http";
            case 110, 995 -> "pop3";
            case 143, 993 -> "imap";
            case 135, 139, 445 -> "smb";
            case 389, 636 -> "ldap";
            case 1433 -> "mssql";
            case 3306, 33060 -> "mysql";
            case 5432 -> "postgresql";
            case 6379 -> "redis";
            case 27017 -> "mongodb";
            case 5900, 5901 -> "vnc";
            case 3389 -> "rdp";
            default -> "tcp";
        };
    }

    private void registerDefaultProbes() {
        // HTTP
        registerProbe(new ServiceProbe(
                "http", "http", "HTTP Server", 100,
                Pattern.compile("(?i)(Server:\\s*([^\\r\\n]+))|(^HTTP/\\d\\.\\d\\s\\d{3})"),
                2, 0.7, List.of("web"), false,
                Set.of(80, 443, 8080, 8443, 8000, 8888, 8008, 8081, 8082, 8083, 8084, 8085, 8086, 8087, 8088, 8089, 8090, 8091, 8092, 8093, 8094, 8095, 8096, 8097, 8098, 8099)
        ));

        // Apache (more specific than generic HTTP — must win on priority)
        registerProbe(new ServiceProbe(
                "apache", "http", "Apache httpd", 110,
                Pattern.compile("(?i)Server:\\s*Apache(?:/([\\d.]+))?"),
                1, 0.85, List.of("web", "apache"), false,
                Set.of(80, 443, 8080, 8443)
        ));

        // Nginx (more specific than generic HTTP — must win on priority)
        registerProbe(new ServiceProbe(
                "nginx", "http", "nginx", 110,
                Pattern.compile("(?i)Server:\\s*nginx(?:/([\\d.]+))?"),
                1, 0.85, List.of("web", "nginx"), false,
                Set.of(80, 443, 8080, 8443)
        ));

        // IIS (more specific than generic HTTP — must win on priority)
        registerProbe(new ServiceProbe(
                "iis", "http", "Microsoft IIS", 110,
                Pattern.compile("(?i)Server:\\s*Microsoft-IIS(?:/([\\d.]+))?"),
                1, 0.85, List.of("web", "iis", "windows"), true,
                Set.of(80, 443, 8080, 8443)
        ));

        // SSH
        registerProbe(new ServiceProbe(
                "ssh", "ssh", "OpenSSH", 100,
                Pattern.compile("(?i)^SSH-(\\d\\.\\d)-([^\\s\\r\\n]+)"),
                2, 0.9, List.of("remote-access", "ssh"), false,
                Set.of(22)
        ));

        // FTP
        registerProbe(new ServiceProbe(
                "ftp", "ftp", "FTP Server", 100,
                Pattern.compile("(?i)^220\\s+([^\\r\\n]+)"),
                1, 0.7, List.of("file-transfer", "ftp"), false,
                Set.of(21, 990)
        ));

        // vsftpd (more specific than generic FTP — must win on priority)
        registerProbe(new ServiceProbe(
                "vsftpd", "ftp", "vsftpd", 110,
                Pattern.compile("(?i)vsftpd(?:\\s+([\\d.]+))?"),
                1, 0.85, List.of("file-transfer", "ftp", "vsftpd"), false,
                Set.of(21, 990)
        ));

        // MySQL
        registerProbe(new ServiceProbe(
                "mysql", "mysql", "MySQL", 100,
                Pattern.compile("(?i)(?:mysql|mariadb)(?:\\s+([\\d.]+))?"),
                1, 0.8, List.of("database", "mysql"), true,
                Set.of(3306, 33060)
        ));

        // PostgreSQL
        registerProbe(new ServiceProbe(
                "postgresql", "postgresql", "PostgreSQL", 100,
                Pattern.compile("(?i)PostgreSQL\\s+([\\d.]+)"),
                1, 0.8, List.of("database", "postgresql"), false,
                Set.of(5432)
        ));

        // Redis
        registerProbe(new ServiceProbe(
                "redis", "redis", "Redis", 100,
                Pattern.compile("(?i)redis_version:([\\d.]+)"),
                1, 0.9, List.of("database", "redis", "cache"), true,
                Set.of(6379)
        ));

        // MongoDB
        registerProbe(new ServiceProbe(
                "mongodb", "mongodb", "MongoDB", 100,
                Pattern.compile("(?i)MongoDB\\s+([\\d.]+)"),
                1, 0.8, List.of("database", "mongodb", "nosql"), true,
                Set.of(27017)
        ));

        // RDP
        registerProbe(new ServiceProbe(
                "rdp", "rdp", "Microsoft RDP", 100,
                Pattern.compile("(?i)Microsoft Terminal Services"),
                0, 0.7, List.of("remote-access", "rdp", "windows"), true,
                Set.of(3389)
        ));

        // SMB
        registerProbe(new ServiceProbe(
                "smb", "smb", "SMB", 100,
                Pattern.compile("(?i)(?:Samba|Windows)\\s+([\\d.]+)"),
                1, 0.7, List.of("file-sharing", "smb"), false,
                Set.of(139, 445)
        ));

        log.info("Registered {} service probes", probes.size());
    }

    public record ServiceProbe(
            String id,
            String protocol,
            String product,
            int priority,
            Pattern pattern,
            int versionGroup,
            double baseConfidence,
            List<String> tags,
            boolean highValueTarget,
            Set<Integer> ports
    ) {
        public boolean matchesPort(int port) {
            return ports.isEmpty() || ports.contains(port);
        }

        public int getPriority() { return priority; }
        public String getProtocol() { return protocol; }
        public String getProduct() { return product; }
        public Pattern getPattern() { return pattern; }
        public int getVersionGroup() { return versionGroup; }
        public double getBaseConfidence() { return baseConfidence; }
        public List<String> getTags() { return tags; }
        public boolean isHighValueTarget() { return highValueTarget; }
    }
}