package com.pila.didcomm;

import com.pila.didcomm.crypto.AesGcm;
import com.pila.didcomm.jwe.JweBuilder;

public final class Encryptor {
    private Encryptor() {}

    public static String encrypt(byte[] key, String plaintext) {
        AesGcm.Result res = AesGcm.encrypt(key, plaintext.getBytes());
        return JweBuilder.build(res.nonce, res.ciphertext, res.tag);
    }
}


