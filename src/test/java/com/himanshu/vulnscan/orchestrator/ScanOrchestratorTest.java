package com.himanshu.vulnscan.orchestrator;

import com.himanshu.vulnscan.model.ScanResult;
import com.himanshu.vulnscan.orchestrator.ScanOrchestrator.ScanConfig;
import com.himanshu.vulnscan.orchestrator.ScanOrchestrator.ScanProgress;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class ScanOrchestratorTest {

    @Test
    void testScanConfig() {
        ScanConfig config = new ScanConfig("top100", 500, 2000, true, "quick", "CVE-2021-44228", "ANON-FTP", false, false);
        assertEquals("top100", config.ports());
        assertEquals(500, config.maxThreads());
        assertEquals(2000, config.timeoutMs());
        assertEquals("quick", config.profile());
    }

    @Test
    void testScanProgress() {
        ScanProgress progress = new ScanProgress("scan-123", 5, 10, "Scanning host", Instant.now());
        assertEquals(50.0, progress.getPercentage());
    }

    @Test
    void testScanResultSummary() {
        ScanResult result = new ScanResult(
                "scan-123", "192.168.1.1", null, "top100", "full",
                Instant.now().minusSeconds(10), Instant.now(),
                Map.of(), Map.of(), Map.of()
        );
        assertEquals(0, result.getTotalHosts());
        assertEquals(0, result.getTotalFindings());
    }
}
