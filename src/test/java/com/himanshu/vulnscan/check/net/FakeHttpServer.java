package com.himanshu.vulnscan.check.net;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * Test fixture: a loopback HTTP server that answers each request with a canned
 * raw response produced by the supplied handler.
 */
public final class FakeHttpServer implements AutoCloseable {

    @FunctionalInterface
    public interface Handler {
        String respond(String request) throws IOException;
    }

    private final ServerSocket serverSocket;
    private final Thread thread;
    private final List<String> requests = new CopyOnWriteArrayList<>();

    private FakeHttpServer(Handler handler) throws IOException {
        this.serverSocket = new ServerSocket(0, 8, InetAddress.getLoopbackAddress());
        this.thread = new Thread(() -> serve(handler), "fake-http");
        this.thread.setDaemon(true);
        this.thread.start();
    }

    public static FakeHttpServer start(Handler handler) throws IOException {
        return new FakeHttpServer(handler);
    }

    public int port() {
        return serverSocket.getLocalPort();
    }

    public List<String> requests() {
        return new ArrayList<>(requests);
    }

    private void serve(Handler handler) {
        while (!serverSocket.isClosed()) {
            try (Socket socket = serverSocket.accept()) {
                socket.setSoTimeout(5000);
                String request = readRequest(socket.getInputStream());
                requests.add(request);
                String response = handler.respond(request);
                if (response != null) {
                    OutputStream out = socket.getOutputStream();
                    out.write(response.getBytes(StandardCharsets.UTF_8));
                    out.flush();
                }
            } catch (IOException e) {
                if (serverSocket.isClosed()) {
                    return;
                }
            }
        }
    }

    private static String readRequest(InputStream in) throws IOException {
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        int next;
        while ((next = in.read()) != -1) {
            buffer.write(next);
            byte[] bytes = buffer.toByteArray();
            int size = bytes.length;
            if (size >= 4
                    && bytes[size - 4] == '\r' && bytes[size - 3] == '\n'
                    && bytes[size - 2] == '\r' && bytes[size - 1] == '\n') {
                break;
            }
            if (size > 65_536) {
                break;
            }
        }
        return buffer.toString(StandardCharsets.UTF_8);
    }

    @Override
    public void close() throws IOException {
        serverSocket.close();
        thread.interrupt();
    }
}
