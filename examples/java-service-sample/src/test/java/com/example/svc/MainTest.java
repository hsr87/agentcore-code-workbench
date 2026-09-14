package com.example.svc;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

class MainTest {
    @Test
    void healthReportsOk() {
        assertEquals("{\"status\":\"ok\"}", Main.health());
    }

    @Test
    void knownOrderIsFound() {
        assertEquals(200, Main.orderStatusCode("1001"));
        assertEquals(404, Main.orderStatusCode("9999"));
    }
}
