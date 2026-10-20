package com.himanshu.vulnscan.check.builtin;

import com.himanshu.vulnscan.check.VulnerabilityCheck;
import com.himanshu.vulnscan.check.net.RdpProbe;
import com.himanshu.vulnscan.model.Finding;
import com.himanshu.vulnscan.model.ServiceFingerprint;

import java.util.List;
import java.util.Optional;

/**
 * BlueKeep exposure requires an RDP service that still allows legacy RDP
 * security (no NLA). The probe reads the negotiation response; it cannot prove
 * the host is unpatched, so the finding is worded as an exposure indicator.
 */
public final class BlueKeepCheck implements VulnerabilityCheck {

    private static final int TIMEOUT_MS = 3000;

    @Override
    public CheckMetadata metadata() {
        return CheckMetadata.builder()
                .id("CVE-2019-0708")
                .name("BlueKeep RDP RCE")
                .description("Pre-authentication remote code execution in RDP")
                .severity(Severity.CRITICAL)
                .cvss(9.8)
                .affectedProducts(List.of("Windows 7, Server 2008 R2, Server 2008"))
                .references(List.of("https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-0708"))
                .tags(List.of("rce", "rdp", "windows", "critical"))
                .build();
    }

    @Override
    public Optional<Finding> execute(ServiceFingerprint fp) {
        if (!"rdp".equals(fp.getProtocol()) || fp.getTarget() == null || fp.getTarget().isBlank()) {
            return Optional.empty();
        }

        return RdpProbe.query(fp.getTarget(), fp.getPort(), TIMEOUT_MS)
                .filter(RdpProbe.Negotiation::acceptsStandardRdpSecurity)
                .map(negotiation -> {
                    String evidence = negotiation.selectedProtocol() == null
                            ? "X.224 connection confirm without an RDP negotiation response"
                            : "RDP negotiation selected PROTOCOL_RDP (no NLA)";
                    return Finding.fromCheck(
                            metadata(),
                            evidence,
                            "The RDP service accepts legacy RDP security, the prerequisite"
                                    + " for BlueKeep exploitation. Verify the host build and"
                                    + " patch level (KB4499175) and require NLA. Affected:"
                                    + " Windows 7, Server 2008 and Server 2008 R2.");
                });
    }
}
