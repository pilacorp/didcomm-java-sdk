package com.pila.didcomm.crypto;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;

public final class AesGcm {
    private AesGcm() {}

    public static class Result {
        public final byte[] nonce;
        public final byte[] ciphertext;
        public final byte[] tag;

        public Result(byte[] nonce, byte[] ciphertext, byte[] tag) {
            this.nonce = nonce;
            this.ciphertext = ciphertext;
            this.tag = tag;
        }
    }

    public static Result encrypt(byte[] key, byte[] plaintext) {
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
            int nonceLen = 12;
            int tagLen = 16;
            byte[] nonce = new byte[nonceLen];
            new SecureRandom().nextBytes(nonce);
            GCMParameterSpec gcmSpec = new GCMParameterSpec(128, nonce);
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmSpec);
            byte[] cipherWithTag = cipher.doFinal(plaintext);
            // Extract tag from last 16 bytes
            byte[] tag = new byte[tagLen];
            byte[] ciphertext = new byte[cipherWithTag.length - tagLen];
            System.arraycopy(cipherWithTag, 0, ciphertext, 0, ciphertext.length);
            System.arraycopy(cipherWithTag, ciphertext.length, tag, 0, tagLen);
            return new Result(nonce, ciphertext, tag);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}


