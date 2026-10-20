package com.himanshu.vulnscan.scanner;

import com.himanshu.vulnscan.model.PortScanResult;
import com.himanshu.vulnscan.model.ServiceFingerprint;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class ServiceDetectorTest {

    @Test
    void testDetectHttpApache() {
        ServiceDetector detector = new ServiceDetector();
        PortScanResult result = PortScanResult.open(80, "HTTP/1.1 200 OK\r\nServer: Apache/2.4.52 (Ubuntu)\r\n\r\n");
        List<ServiceFingerprint> fingerprints = detector.detect("192.168.1.1", List.of(result));

        assertFalse(fingerprints.isEmpty());
        ServiceFingerprint fp = fingerprints.get(0);
        assertEquals("Apache httpd", fp.getProduct());
        assertEquals("2.4.52", fp.getVersion());
        assertEquals("http", fp.getProtocol());
        assertTrue(fp.getConfidence() > 0.8);
    }

    @Test
    void testDetectHttpNginx() {
        ServiceDetector detector = new ServiceDetector();
        PortScanResult result = PortScanResult.open(8080, "HTTP/1.1 200 OK\r\nServer: nginx/1.22.0\r\n\r\n");
        List<ServiceFingerprint> fingerprints = detector.detect("192.168.1.1", List.of(result));

        assertFalse(fingerprints.isEmpty());
        ServiceFingerprint fp = fingerprints.get(0);
        assertEquals("nginx", fp.getProduct());
        assertEquals("1.22.0", fp.getVersion());
    }

    @Test
    void testDetectHttpIIS() {
        ServiceDetector detector = new ServiceDetector();
        PortScanResult result = PortScanResult.open(443, "HTTP/1.1 200 OK\r\nServer: Microsoft-IIS/10.0\r\n\r\n");
        List<ServiceFingerprint> fingerprints = detector.detect("192.168.1.1", List.of(result));

        assertFalse(fingerprints.isEmpty());
        ServiceFingerprint fp = fingerprints.get(0);
        assertEquals("Microsoft IIS", fp.getProduct());
        assertEquals("10.0", fp.getVersion());
        assertTrue(fp.getTags().contains("windows"));
        assertTrue(fp.getTags().contains("high-value"));
    }

    @Test
    void testDetectSSH() {
        ServiceDetector detector = new ServiceDetector();
        PortScanResult result = PortScanResult.open(22, "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1");
        List<ServiceFingerprint> fingerprints = detector.detect("192.168.1.1", List.of(result));

        assertFalse(fingerprints.isEmpty());
        ServiceFingerprint fp = fingerprints.get(0);
        assertEquals("OpenSSH", fp.getProduct());
        assertEquals("OpenSSH_8.9p1", fp.getVersion());
        assertEquals("ssh", fp.getProtocol());
    }

    @Test
    void testDetectFTP() {
        ServiceDetector detector = new ServiceDetector();
        PortScanResult result = PortScanResult.open(21, "220 (vsFTPd 3.0.5)");
        List<ServiceFingerprint> fingerprints = detector.detect("192.168.1.1", List.of(result));

        assertFalse(fingerprints.isEmpty());
        ServiceFingerprint fp = fingerprints.get(0);
        assertEquals("vsftpd", fp.getProduct());
        assertEquals("3.0.5", fp.getVersion());
    }

    @Test
    void testDetectMySQL() {
        ServiceDetector detector = new ServiceDetector();
        PortScanResult result = PortScanResult.open(3306, "mysql 5.7.42-0ubuntu0.18.04.1");
        List<ServiceFingerprint> fingerprints = detector.detect("192.168.1.1", List.of(result));

        assertFalse(fingerprints.isEmpty());
        ServiceFingerprint fp = fingerprints.get(0);
        assertEquals("MySQL", fp.getProduct());
        assertTrue(fp.getTags().contains("database"));
    }

    @Test
    void testDetectPostgreSQL() {
        ServiceDetector detector = new ServiceDetector();
        PortScanResult result = PortScanResult.open(5432, "PostgreSQL 15.3 on x86_64-pc-linux-gnu");
        List<ServiceFingerprint> fingerprints = detector.detect("192.168.1.1", List.of(result));

        assertFalse(fingerprints.isEmpty());
        ServiceFingerprint fp = fingerprints.get(0);
        assertEquals("PostgreSQL", fp.getProduct());
        assertEquals("15.3", fp.getVersion());
    }

    @Test
    void testDetectRedis() {
        ServiceDetector detector = new ServiceDetector();
        PortScanResult result = PortScanResult.open(6379, "$8\r\nredis_version:7.0.12\r\n");
        List<ServiceFingerprint> fingerprints = detector.detect("192.168.1.1", List.of(result));

        assertFalse(fingerprints.isEmpty());
        ServiceFingerprint fp = fingerprints.get(0);
        assertEquals("Redis", fp.getProduct());
        assertEquals("7.0.12", fp.getVersion());
        assertTrue(fp.getConfidence() > 0.9);
    }

    @Test
    void testDetectMongoDB() {
        ServiceDetector detector = new ServiceDetector();
        PortScanResult result = PortScanResult.open(27017, "MongoDB 6.0.5");
        List<ServiceFingerprint> fingerprints = detector.detect("192.168.1.1", List.of(result));

        assertFalse(fingerprints.isEmpty());
        ServiceFingerprint fp = fingerprints.get(0);
        assertEquals("MongoDB", fp.getProduct());
        assertEquals("6.0.5", fp.getVersion());
    }

    @Test
    void testDetectRDP() {
        ServiceDetector detector = new ServiceDetector();
        PortScanResult result = PortScanResult.open(3389, "Microsoft Terminal Services");
        List<ServiceFingerprint> fingerprints = detector.detect("192.168.1.1", List.of(result));

        assertFalse(fingerprints.isEmpty());
        ServiceFingerprint fp = fingerprints.get(0);
        assertEquals("Microsoft RDP", fp.getProduct());
        assertEquals("rdp", fp.getProtocol());
        assertTrue(fp.getTags().contains("high-value"));
    }

    @Test
    void testGenericFallback() {
        ServiceDetector detector = new ServiceDetector();
        PortScanResult result = PortScanResult.open(12345, "Some unknown service banner");
        List<ServiceFingerprint> fingerprints = detector.detect("192.168.1.1", List.of(result));

        assertFalse(fingerprints.isEmpty());
        ServiceFingerprint fp = fingerprints.get(0);
        assertEquals("unknown", fp.getProduct());
        assertEquals("tcp", fp.getProtocol());
        assertEquals(0.1, fp.getConfidence());
    }

    @Test
    void testMultiplePorts() {
        ServiceDetector detector = new ServiceDetector();
        List<PortScanResult> results = List.of(
                PortScanResult.open(80, "Server: Apache/2.4.41"),
                PortScanResult.open(22, "SSH-2.0-OpenSSH_8.2p1"),
                PortScanResult.open(3306, "mysql 8.0.33")
        );
        List<ServiceFingerprint> fingerprints = detector.detect("192.168.1.1", results);

        assertEquals(3, fingerprints.size());
        assertTrue(fingerprints.stream().anyMatch(f -> f.getProduct().equals("Apache httpd")));
        assertTrue(fingerprints.stream().anyMatch(f -> f.getProduct().equals("OpenSSH")));
        assertTrue(fingerprints.stream().anyMatch(f -> f.getProduct().equals("MySQL")));
    }

    @Test
    void testFingerprintCarriesTarget() {
        ServiceDetector detector = new ServiceDetector();
        List<PortScanResult> results = List.of(PortScanResult.open(22, "SSH-2.0-OpenSSH_8.9p1"));
        List<ServiceFingerprint> fingerprints = detector.detect("scanme.example", results);

        assertEquals("scanme.example", fingerprints.get(0).getTarget());
    }
}