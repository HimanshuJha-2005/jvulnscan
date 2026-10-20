package com.himanshu.vulnscan;

import com.himanshu.vulnscan.model.ScanResult;
import com.himanshu.vulnscan.orchestrator.ScanOrchestrator;
import com.himanshu.vulnscan.output.OutputFormatter;
import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;

import java.io.IOException;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Locale;
import java.util.concurrent.Callable;

@Command(name = "scan",
        description = "Scan targets for open ports and vulnerabilities",
        mixinStandardHelpOptions = true)
public class ScanCommand implements Callable<Integer> {

    @Parameters(index = "0", description = "Target specification (IP, CIDR, range, hostname, or file with -iL)")
    private String target;

    @Option(names = {"-p", "--ports"}, description = "Port specification (e.g., 80,443, 1-1000, top100, top1000, all)")
    private String ports = "top1000";

    @Option(names = {"-t", "--threads"}, description = "Maximum concurrent threads (virtual threads)")
    private int threads = 1000;

    @Option(names = {"-T", "--timeout"}, description = "Connection timeout in milliseconds")
    private int timeout = 3000;

    @Option(names = {"-o", "--output"}, description = "Output file (default: stdout)")
    private String output;

    @Option(names = {"-f", "--format"}, description = "Output format: json, csv, sarif, table, json-lines")
    private String format = "table";

    @Option(names = {"-P", "--profile"}, description = "Scan profile: quick, full, stealth, custom")
    private String profile = "full";

    @Option(names = {"-iL", "--input-file"}, description = "Read targets from file")
    private String inputFile;

    @Option(names = {"--checks"}, description = "Comma-separated check IDs to run (default: all)")
    private String checks;

    @Option(names = {"--exclude-checks"}, description = "Comma-separated check IDs to skip")
    private String excludeChecks;

    @Option(names = {"--resume"}, description = "Resume previous scan by ID")
    private String resume;

    @Option(names = {"--no-ping"}, description = "Skip host discovery")
    private boolean noPing = false;

    @Option(names = {"--no-banner-grab"}, description = "Disable banner grabbing on open ports")
    private boolean noBannerGrab = false;

    @Option(names = {"--no-progress"}, description = "Disable progress bar")
    private boolean noProgress = false;

    @Option(names = {"--active"},
            description = "Enable intrusive checks (default-credential attempts, payload injection). "
                    + "Only use against systems you are authorised to test.")
    private boolean activeChecks = false;

    @Override
    public Integer call() {
        ScanOrchestrator.ScanConfig config = new ScanOrchestrator.ScanConfig(
                ports, threads, timeout, !noBannerGrab, profile, checks, excludeChecks, noPing, activeChecks
        );

        ScanOrchestrator orchestrator = new ScanOrchestrator(config);
        OutputFormatter formatter = new OutputFormatter();

        if (!noProgress) {
            orchestrator.setProgressCallback(progress -> {
                System.err.print(formatter.formatProgress(progress));
            });
        }

        // Diagnostics go to stderr so stdout carries only the scan result
        // (safe for pipes: vulnscan scan ... -f json > results.json).
        System.err.println("Starting scan...");
        ScanResult result = orchestrator.execute(target, inputFile, resume);

        if (!noProgress) {
            System.err.println(); // New line after progress bar
        }

        String formatted = formatter.format(result, OutputFormatter.Format.valueOf(format.toUpperCase(Locale.ROOT).replace("-", "_")));

        if (output != null) {
            try (PrintWriter writer = new PrintWriter(Files.newBufferedWriter(Paths.get(output), StandardCharsets.UTF_8))) {
                writer.print(formatted);
                System.err.println("Results written to " + output);
            } catch (IOException e) {
                System.err.println("Failed to write output: " + e.getMessage());
                return 1;
            }
        } else {
            System.out.println(formatted);
        }

        return result.getCriticalFindings() > 0 ? 2 : (result.getTotalFindings() > 0 ? 1 : 0);
    }
}