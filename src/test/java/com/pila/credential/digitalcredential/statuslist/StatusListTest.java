package com.pila.credential.digitalcredential.statuslist;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

public class StatusListTest {
    @Test
    void getSetRoundTripAndEncodeDecode() throws Exception {
        StatusList list = StatusList.create(16, 1);
        list.set(3, 1);
        list.set(7, 1);
        assertEquals(1, list.get(3));
        assertEquals(0, list.get(0));
        assertEquals(1, list.get(7));
        StatusList decoded = StatusList.decode(list.encode(), 1);
        assertEquals(1, decoded.get(3));
        assertEquals(1, decoded.get(7));
        assertEquals(0, decoded.get(2));
    }

    @Test
    void twoBitValues() throws Exception {
        StatusList list = StatusList.create(8, 2);
        list.set(0, 3);
        list.set(1, 1);
        assertEquals(3, list.get(0));
        assertEquals(1, list.get(1));
        assertThrows(Exception.class, () -> list.set(0, 4));
        assertThrows(Exception.class, () -> list.get(99));
    }
}
