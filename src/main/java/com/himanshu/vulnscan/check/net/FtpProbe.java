package com.himanshu.vulnscan.check.net;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.Optional;

/**
 * Minimal FTP login used by the opt-in default-credentials check. It only
 * sends USER/PASS and reads reply codes; it never lists or downloads files.
 */
public final class FtpProbe {

    private FtpProbe() {
    }

    /**
     * Attempts a login and returns evidence when the server answers 230
     * (logged in). Empty means the credentials were rejected or the service
     * did not speak enough FTP to decide.
     */
    public static Optional<String> login(String host, int port, String username, String password,
                                         int timeoutMs) {
        if (host == null || host.isBlank()) {
            return Optional.empty();
        }

        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(host, port), timeoutMs);
            socket.setSoTimeout(timeoutMs);

            BufferedReader in = new BufferedReader(
                    new InputStreamReader(socket.getInputStream(), StandardCharsets.US_ASCII));
            Writer out = new BufferedWriter(
                    new OutputStreamWriter(socket.getOutputStream(), StandardCharsets.US_ASCII));

            if (readReplyCode(in) != 220) {
                return Optional.empty();
            }

            send(out, "USER " + username);
            int code = readReplyCode(in);
            if (code == 230) {
                quit(out);
                return Optional.of("USER " + username + " -> 230 (no password required)");
            }
            if (code != 331) {
                quit(out);
                return Optional.empty();
            }

            send(out, "PASS " + password);
            code = readReplyCode(in);
            quit(out);

            if (code == 230 || code == 202) {
                return Optional.of("USER " + username + " / default password -> " + code + " login accepted");
            }
            return Optional.empty();
        } catch (IOException | RuntimeException e) {
            return Optional.empty();
        }
    }

    private static void send(Writer out, String line) throws IOException {
        out.write(line + "\r\n");
        out.flush();
    }

    private static void quit(Writer out) {
        try {
            send(out, "QUIT");
        } catch (IOException ignored) {
            // Best effort; the finding does not depend on a clean logout.
        }
    }

    static int readReplyCode(BufferedReader in) throws IOException {
        String line = in.readLine();
        if (line == null || line.length() < 3) {
            return -1;
        }
        int code;
        try {
            code = Integer.parseInt(line.substring(0, 3));
        } catch (NumberFormatException e) {
            return -1;
        }

        boolean multiline = line.length() > 3 && line.charAt(3) == '-';
        int lines = 1;
        while (multiline && lines < 20) {
            String next = in.readLine();
            if (next == null) {
                return -1;
            }
            lines++;
            if (next.startsWith(code + " ")) {
                break;
            }
        }
        return code;
    }
}
