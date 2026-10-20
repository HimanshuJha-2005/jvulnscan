package com.himanshu.vulnscan.check.net;

import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class TlsProbeTest {

    @Test
    void clientHelloIncludesSniOnlyForHostnames() {
        byte[] withSni = TlsProbe.clientHello("example.com", 0x0303, List.of(0x002F));
        byte[] withoutSni = TlsProbe.clientHello("127.0.0.1", 0x0303, List.of(0x002F));

        assertTrue(new String(withSni, StandardCharsets.US_ASCII).contains("example.com"));
        assertFalse(new String(withoutSni, StandardCharsets.US_ASCII).contains("example.com"));
        assertEquals(0x16, withSni[0] & 0xFF);
        assertEquals(1, withSni[5] & 0xFF);
    }

    @Test
    void parsesServerHelloVersionFromHeader() {
        byte[] hello = serverHello(0x0302, 0xC013, null);

        TlsProbe.ServerHello parsed = TlsProbe.parseServerHello(hello).orElseThrow();

        assertEquals(0x0302, parsed.protocolVersion());
        assertEquals(0xC013, parsed.cipherSuite());
        assertEquals("TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA", parsed.cipherName());
    }

    @Test
    void prefersSupportedVersionsExtension() {
        byte[] hello = serverHello(0x0303, 0x1301, 0x0304);

        TlsProbe.ServerHello parsed = TlsProbe.parseServerHello(hello).orElseThrow();

        assertEquals(0x0304, parsed.protocolVersion());
        assertEquals("TLS 1.3", parsed.protocolName());
    }

    @Test
    void rejectsMalformedMessages() {
        assertTrue(TlsProbe.parseServerHello(null).isEmpty());
        assertTrue(TlsProbe.parseServerHello(new byte[]{2, 0, 0}).isEmpty());
        assertTrue(TlsProbe.parseServerHello(new byte[]{1, 0, 0, 38}).isEmpty());

        byte[] hello = serverHello(0x0303, 0xC02F, null);
        hello[3] = 100; // claim more bytes than available
        assertTrue(TlsProbe.parseServerHello(hello).isEmpty());
    }

    private static byte[] serverHello(int version, int cipher, Integer negotiatedVersion) {
        ByteArrayOutputStream body = new ByteArrayOutputStream();
        body.write((version >>> 8) & 0xFF);
        body.write(version & 0xFF);
        body.write(new byte[32], 0, 32);
        body.write(0); // empty session id
        body.write((cipher >>> 8) & 0xFF);
        body.write(cipher & 0xFF);
        body.write(0); // compression

        byte[] extensions = new byte[0];
        if (negotiatedVersion != null) {
            extensions = new byte[]{
                    0x00, 0x2B, 0x00, 0x02,
                    (byte) ((negotiatedVersion >>> 8) & 0xFF), (byte) (negotiatedVersion & 0xFF)
            };
        }
        body.write((extensions.length >>> 8) & 0xFF);
        body.write(extensions.length & 0xFF);
        body.write(extensions, 0, extensions.length);

        byte[] bodyBytes = body.toByteArray();
        ByteArrayOutputStream handshake = new ByteArrayOutputStream();
        handshake.write(2);
        handshake.write((bodyBytes.length >>> 16) & 0xFF);
        handshake.write((bodyBytes.length >>> 8) & 0xFF);
        handshake.write(bodyBytes.length & 0xFF);
        handshake.write(bodyBytes, 0, bodyBytes.length);
        return handshake.toByteArray();
    }
}
