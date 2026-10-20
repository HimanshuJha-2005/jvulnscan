package com.himanshu.vulnscan.check.net;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;

/**
 * Test fixture: a tiny FTP server that accepts exactly one username/password
 * pair and logs the commands it received.
 */
public final class FakeFtpServer implements AutoCloseable {

    private final ServerSocket serverSocket;
    private final Thread thread;
    private final String username;
    private final String password;

    private FakeFtpServer(String username, String password) throws IOException {
        this.username = username;
        this.password = password;
        this.serverSocket = new ServerSocket(0, 8, InetAddress.getLoopbackAddress());
        this.thread = new Thread(this::serve, "fake-ftp");
        this.thread.setDaemon(true);
        this.thread.start();
    }

    public static FakeFtpServer start(String username, String password) throws IOException {
        return new FakeFtpServer(username, password);
    }

    public int port() {
        return serverSocket.getLocalPort();
    }

    private void serve() {
        while (!serverSocket.isClosed()) {
            try (Socket socket = serverSocket.accept()) {
                socket.setSoTimeout(5000);
                handle(socket);
            } catch (IOException e) {
                if (serverSocket.isClosed()) {
                    return;
                }
            }
        }
    }

    private void handle(Socket socket) throws IOException {
        BufferedReader in = new BufferedReader(
                new InputStreamReader(socket.getInputStream(), StandardCharsets.US_ASCII));
        Writer out = new BufferedWriter(
                new OutputStreamWriter(socket.getOutputStream(), StandardCharsets.US_ASCII));

        write(out, "220-Fake FTP server");
        write(out, "220 Ready");

        boolean userAccepted = false;
        String line;
        while ((line = in.readLine()) != null) {
            String upper = line.toUpperCase(java.util.Locale.ROOT);
            if (upper.startsWith("USER ")) {
                userAccepted = username.equals(line.substring(5).trim());
                write(out, userAccepted ? "331 Password required" : "530 Login incorrect");
            } else if (upper.startsWith("PASS ")) {
                boolean accepted = userAccepted && password.equals(line.substring(5).trim());
                write(out, accepted ? "230 Login successful" : "530 Login incorrect");
                if (accepted) {
                    return;
                }
            } else if (upper.equals("QUIT")) {
                write(out, "221 Bye");
                return;
            } else {
                write(out, "500 Unknown command");
            }
        }
    }

    private static void write(Writer out, String line) throws IOException {
        out.write(line + "\r\n");
        out.flush();
    }

    @Override
    public void close() throws IOException {
        serverSocket.close();
        thread.interrupt();
    }
}
