package com.example.svc;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.Map;

/** A small backend service: /health and /orders/{id}. Stands in for a large Gradle service in the demo. */
public class Main {
    static final Map<String, String> ORDERS = Map.of("1001", "shipped", "1002", "packed");

    public static String health() {
        return "{\"status\":\"ok\"}";
    }

    public static int orderStatusCode(String id) {
        return ORDERS.containsKey(id) ? 200 : 404;
    }

    public static void main(String[] args) throws IOException {
        int port = Integer.parseInt(System.getenv().getOrDefault("PORT", "8081"));
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", port), 0);
        server.createContext("/health", ex -> reply(ex, 200, health()));
        server.createContext("/orders/", ex -> {
            String id = ex.getRequestURI().getPath().substring("/orders/".length());
            int code = orderStatusCode(id);
            reply(ex, code, code == 200 ? "{\"id\":\"" + id + "\",\"status\":\"" + ORDERS.get(id) + "\"}" : "{\"error\":\"not found\"}");
        });
        server.start();
        System.out.println("order-service listening on " + port);
    }

    private static void reply(HttpExchange ex, int code, String body) throws IOException {
        byte[] data = body.getBytes(StandardCharsets.UTF_8);
        ex.getResponseHeaders().add("Content-Type", "application/json");
        ex.sendResponseHeaders(code, data.length);
        try (OutputStream out = ex.getResponseBody()) { out.write(data); }
    }
}
