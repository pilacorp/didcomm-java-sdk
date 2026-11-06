package com.pila.credential.common.processor;

import com.pila.credential.didv2.Rfc8785;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/** Expected values observed by running go-credential-sdk's jsoncanonicalizer.Transform. */
class Rfc8785GoParityTest {

    private static String jcs(String in) throws Exception {
        return new String(Rfc8785.transform(in.getBytes(StandardCharsets.UTF_8)), StandardCharsets.UTF_8);
    }

    @Test
    void numbersFollowEs6LikeGo() throws Exception {
        assertEquals("{\"a\":10000000}", jcs("{\"a\":1e7}"));
        assertEquals("{\"a\":12345678}", jcs("{\"a\":12345678}"));
        assertEquals("{\"a\":0.0001}", jcs("{\"a\":1e-4}"));
        assertEquals("{\"a\":1e+21}", jcs("{\"a\":1e21}"));
        assertEquals("{\"a\":1.2345678e+25}", jcs("{\"a\":1.2345678e25}"));
        assertEquals("{\"a\":0.000001}", jcs("{\"a\":0.000001}"));
        assertEquals("{\"a\":1e-7}", jcs("{\"a\":1e-7}"));
        assertEquals("{\"a\":0}", jcs("{\"a\":-0}"));
        assertEquals("{\"a\":100,\"b\":1.5}", jcs("{\"a\":100,\"b\":1.5}"));
        assertEquals("{\"a\":0.1,\"b\":123456789012345680000}", jcs("{\"a\":0.1,\"b\":123456789012345678901}"));
        assertEquals("{\"a\":1e+300,\"c\":5e-324}", jcs("{\"a\":1e300,\"c\":5e-324}"));
    }

    @Test
    void rejectsWhatGoRejects() {
        assertThrows(Exception.class, () -> jcs("{\"a\":1,\"a\":2}")); // duplicate key
        assertThrows(Exception.class, () -> jcs("1")); // top-level scalar
        assertThrows(Exception.class, () -> jcs("\"x\""));
        assertThrows(Exception.class, () -> jcs("{\"a\":\"\\ud800\"}")); // lone surrogate
    }

    @Test
    void sortsAndEscapesLikeGo() throws Exception {
        assertEquals("[3,1,{\"a\":2,\"b\":1}]", jcs("[3,1,{\"b\":1,\"a\":2}]"));
        assertEquals("{\"a\":\"\u20ac\\n\",\"b\":\"\u00e9\"}", jcs("{\"b\":\"\\u00e9\",\"a\":\"\\u20ac\\n\"}"));
        assertEquals("{\"a\":\"\uD83D\uDE00\"}", jcs("{\"a\":\"\\ud83d\\ude00\"}"));
    }
}
