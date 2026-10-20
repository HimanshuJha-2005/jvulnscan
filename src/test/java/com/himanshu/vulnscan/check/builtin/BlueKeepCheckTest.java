package com.himanshu.vulnscan.check.builtin;

import com.himanshu.vulnscan.check.net.FakeRdpServer;
import com.himanshu.vulnscan.check.net.RdpProbe;
import com.himanshu.vulnscan.model.Finding;
import com.himanshu.vulnscan.model.ServiceFingerprint;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import java.io.IOException;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

@Timeout(20)
class BlueKeepCheckTest {

    @Test
    void recognizesStandardRdpSecurity() {
        RdpProbe.Negotiation negotiation = RdpProbe.parseResponse(confirm(0)).orElseThrow();

        assertTrue(negotiation.connectionConfirmed());
        assertEquals(0, negotiation.selectedProtocol());
        assertTrue(negotiation.acceptsStandardRdpSecurity());
    }

    @Test
    void recognizesNlaAsNotExposed() {
        RdpProbe.Negotiation negotiation = RdpProbe.parseResponse(confirm(2)).orElseThrow();

        assertTrue(negotiation.requiresNla());
        assertFalse(negotiation.acceptsStandardRdpSecurity());
    }

    @Test
    void treatsMissingNegotiationAsLegacyServer() {
        RdpProbe.Negotiation negotiation = RdpProbe.parseResponse(
                new byte[]{0x03, 0x00, 0x00, 0x0B, 0x06, (byte) 0xD0, 0, 0, 0, 0, 0}).orElseThrow();

        assertNull(negotiation.selectedProtocol());
        assertTrue(negotiation.acceptsStandardRdpSecurity());
    }

    @Test
    void reportsHostWithoutNla() throws IOException {
        try (FakeRdpServer server = FakeRdpServer.start(FakeRdpServer.Mode.STANDARD_RDP)) {
            Optional<Finding> finding = new BlueKeepCheck().execute(fingerprint(server.port()));

            assertTrue(finding.isPresent());
            assertEquals("CVE-2019-0708", finding.get().getCheckId());
            assertTrue(finding.get().getEvidence().contains("PROTOCOL_RDP"));
        }
    }

    @Test
    void reportsLegacyServerWithoutNegotiation() throws IOException {
        try (FakeRdpServer server = FakeRdpServer.start(FakeRdpServer.Mode.NO_NEGOTIATION)) {
            Optional<Finding> finding = new BlueKeepCheck().execute(fingerprint(server.port()));

            assertTrue(finding.isPresent());
            assertTrue(finding.get().getEvidence().contains("without an RDP negotiation response"));
        }
    }

    @Test
    void staysQuietWhenNlaIsRequired() throws IOException {
        try (FakeRdpServer server = FakeRdpServer.start(FakeRdpServer.Mode.NLA)) {
            assertTrue(new BlueKeepCheck().execute(fingerprint(server.port())).isEmpty());
        }
    }

    @Test
    void staysQuietWhenConnectionIsRejected() throws IOException {
        try (FakeRdpServer server = FakeRdpServer.start(FakeRdpServer.Mode.DISCONNECT)) {
            assertTrue(new BlueKeepCheck().execute(fingerprint(server.port())).isEmpty());
        }
    }

    @Test
    void ignoresNonRdpFingerprints() {
        ServiceFingerprint http = new ServiceFingerprint(
                "127.0.0.1", 80, "http", "nginx", "1.24", 0.9, "HTTP/1.1 200 OK", List.of("web"));
        ServiceFingerprint noTarget = new ServiceFingerprint(
                3389, "rdp", "Microsoft RDP", null, 0.7, "Microsoft Terminal Services", List.of("rdp"));

        assertTrue(new BlueKeepCheck().execute(http).isEmpty());
        assertTrue(new BlueKeepCheck().execute(noTarget).isEmpty());
    }

    private static byte[] confirm(int selectedProtocol) {
        return new byte[]{
                0x03, 0x00, 0x00, 0x13,
                0x0E, (byte) 0xD0,
                0x00, 0x00, 0x00, 0x00, 0x00,
                0x02, 0x00, 0x08, 0x00,
                (byte) selectedProtocol, 0x00, 0x00, 0x00
        };
    }

    private static ServiceFingerprint fingerprint(int port) {
        return new ServiceFingerprint(
                "127.0.0.1", port, "rdp", "Microsoft RDP", null, 0.7,
                "Microsoft Terminal Services", List.of("rdp", "high-value"));
    }
}
