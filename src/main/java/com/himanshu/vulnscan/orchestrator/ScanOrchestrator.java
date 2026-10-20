package com.himanshu.vulnscan.orchestrator;

import com.himanshu.vulnscan.check.CheckRegistry;
import com.himanshu.vulnscan.check.VulnerabilityCheck;
import com.himanshu.vulnscan.model.Finding;
import com.himanshu.vulnscan.model.PortScanResult;
import com.himanshu.vulnscan.model.ScanResult;
import com.himanshu.vulnscan.model.ServiceFingerprint;
import com.himanshu.vulnscan.persistence.ScanStateStore;
import com.himanshu.vulnscan.scanner.PortScanner;
import com.himanshu.vulnscan.scanner.ServiceDetector;
import com.himanshu.vulnscan.scanner.TargetParser;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Consumer;

public class ScanOrchestrator {

    private static final Logger log = LoggerFactory.getLogger(ScanOrchestrator.class);

    private final PortScanner portScanner;
    private final ServiceDetector serviceDetector;
    private final CheckRegistry checkRegistry;
    private final ScanConfig config;

    private Consumer<ScanProgress> progressCallback;

    public ScanOrchestrator(ScanConfig config) {
        this.config = config;
        this.portScanner = new PortScanner(config.timeoutMs(), config.maxThreads(), config.bannerGrab());
        this.serviceDetector = new ServiceDetector();
        this.checkRegistry = new CheckRegistry(config.activeChecks());
    }

    public void setProgressCallback(Consumer<ScanProgress> callback) {
        this.progressCallback = callback;
    }

    public ScanResult execute(String target, String inputFile) {
        return execute(target, inputFile, null);
    }

    public ScanResult execute(String target, String inputFile, String resumeScanId) {
        Instant start = Instant.now();
        String scanId = UUID.randomUUID().toString();

        log.info("Starting scan {} for target: {}", scanId, target != null ? target : "@" + inputFile);

        // Parse targets
        List<String> targets = TargetParser.parse(target, inputFile);
        reportProgress(scanId, 0, targets.size(), "Target parsing complete: " + targets.size() + " hosts");

        // Resume: skip hosts already completed in a previous scan.
        ScanStateStore store = new ScanStateStore();
        Set<String> skippedHosts = new java.util.HashSet<>();
        if (resumeScanId != null && !resumeScanId.isBlank()) {
            ScanResult previous = store.loadScanResult(resumeScanId);
            if (previous == null) {
                log.warn("Resume scan ID {} not found, starting fresh", resumeScanId);
            } else {
                skippedHosts.addAll(store.getCompletedHosts(resumeScanId));
                log.info("Resuming: skipping {} already-completed hosts from scan {}", skippedHosts.size(), resumeScanId);
            }
        }

        // Parse ports
        Set<Integer> ports = PortScanner.parsePortSpec(config.ports());
        reportProgress(scanId, 0, targets.size(), "Port spec parsed: " + ports.size() + " ports");

        // Apply check filters
        if (config.checks() != null && !config.checks().isBlank()) {
            Set<String> checkIds = Set.of(config.checks().split("\\s*,\\s*"));
            checkRegistry.enableOnly(checkIds);
        }
        if (config.excludeChecks() != null && !config.excludeChecks().isBlank()) {
            Set<String> checkIds = Set.of(config.excludeChecks().split("\\s*,\\s*"));
            checkRegistry.disableAll(checkIds);
        }

        // Scan each target
        Map<String, List<PortScanResult>> allPortResults = new ConcurrentHashMap<>();
        Map<String, List<ServiceFingerprint>> allFingerprints = new ConcurrentHashMap<>();
        Map<String, List<Finding>> allFindings = new ConcurrentHashMap<>();

        AtomicInteger completedHosts = new AtomicInteger(0);

        for (String host : targets) {
            if (skippedHosts.contains(host)) {
                log.debug("Host {} already completed in resumed scan, skipping", host);
                // Carry over previous results for skipped hosts.
                ScanResult previous = store.loadScanResult(resumeScanId);
                if (previous != null) {
                    if (previous.getPortResults().containsKey(host)) {
                        allPortResults.put(host, previous.getPortResults().get(host));
                    }
                    if (previous.getFingerprints().containsKey(host)) {
                        allFingerprints.put(host, previous.getFingerprints().get(host));
                    }
                    if (previous.getFindings().containsKey(host)) {
                        allFindings.put(host, previous.getFindings().get(host));
                    }
                }
                completedHosts.incrementAndGet();
                continue;
            }
            if (config.noPing() || isHostAlive(host)) {
                reportProgress(scanId, completedHosts.get(), targets.size(), "Scanning " + host);

                // Port scan
                List<PortScanResult> portResults = portScanner.scan(host, ports);
                allPortResults.put(host, portResults);

                // Service detection
                List<ServiceFingerprint> fingerprints = serviceDetector.detect(host, portResults);
                allFingerprints.put(host, fingerprints);

                // Vulnerability checks
                List<Finding> findings = new ArrayList<>();
                for (ServiceFingerprint fp : fingerprints) {
                    findings.addAll(checkRegistry.executeChecks(fp));
                }
                allFindings.put(host, findings);

                // Persist per-host so a later --resume can skip it.
                store.saveHostResult(scanId, host, portResults, fingerprints, findings);

                int done = completedHosts.incrementAndGet();
                reportProgress(scanId, done, targets.size(), "Completed " + host + " (" + portResults.stream().filter(PortScanResult::isOpen).count() + " open ports, " + findings.size() + " findings)");
            } else {
                log.debug("Host {} appears down, skipping", host);
                completedHosts.incrementAndGet();
            }
        }

        Instant end = Instant.now();

        ScanResult result = new ScanResult(
                scanId,
                target,
                inputFile,
                config.ports(),
                config.profile(),
                start,
                end,
                allPortResults,
                allFingerprints,
                allFindings
        );

        store.saveScan(result, "COMPLETED", targets.size(), targets.size(), "Scan complete");

        log.info("Scan {} completed in {}ms. Total hosts: {}, Total findings: {}",
                scanId, java.time.Duration.between(start, end).toMillis(),
                targets.size(), allFindings.values().stream().mapToInt(List::size).sum());

        reportProgress(scanId, targets.size(), targets.size(), "Scan complete");
        return result;
    }

    private boolean isHostAlive(String host) {
        try (var socket = new java.net.Socket()) {
            socket.connect(new java.net.InetSocketAddress(host, 80), 1000);
            return true;
        } catch (java.io.IOException e) {
            try (var socket = new java.net.Socket()) {
                socket.connect(new java.net.InetSocketAddress(host, 443), 1000);
                return true;
            } catch (java.io.IOException ignored) {
                return false;
            }
        }
    }

    private void reportProgress(String scanId, int current, int total, String message) {
        if (progressCallback != null) {
            progressCallback.accept(new ScanProgress(scanId, current, total, message, Instant.now()));
        }
    }

    public record ScanConfig(
            String ports,
            int maxThreads,
            int timeoutMs,
            boolean bannerGrab,
            String profile,
            String checks,
            String excludeChecks,
            boolean noPing,
            boolean activeChecks
    ) {}

    public record ScanProgress(
            String scanId,
            int current,
            int total,
            String message,
            Instant timestamp
    ) {
        public double getPercentage() {
            return total > 0 ? (double) current / total * 100 : 0;
        }
    }
}