package com.pila.didcomm;

import com.fasterxml.jackson.databind.ObjectMapper;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;
import java.util.Map;

public final class Decryptor {
    private Decryptor() {}

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final Base64.Decoder URL_DECODER = Base64.getUrlDecoder();

    public static String decrypt(String jweStr, byte[] sharedKey) {
        try {
            Map<?,?> jwe = MAPPER.readValue(jweStr, Map.class);
            byte[] iv = URL_DECODER.decode((String) jwe.get("iv"));
            byte[] ciphertext = URL_DECODER.decode((String) jwe.get("ciphertext"));
            byte[] tag = URL_DECODER.decode((String) jwe.get("tag"));

            // Try with real tag first
            try {
                byte[] ciphertextWithTag = new byte[ciphertext.length + tag.length];
                System.arraycopy(ciphertext, 0, ciphertextWithTag, 0, ciphertext.length);
                System.arraycopy(tag, 0, ciphertextWithTag, ciphertext.length, tag.length);

                Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
                SecretKeySpec keySpec = new SecretKeySpec(sharedKey, "AES");
                GCMParameterSpec gcmSpec = new GCMParameterSpec(128, iv);
                cipher.init(Cipher.DECRYPT_MODE, keySpec, gcmSpec);
                byte[] plaintext = cipher.doFinal(ciphertextWithTag);
                return new String(plaintext);
            } catch (Exception e) {
                // Fallback to mock tag for backward compatibility (Go uses sharedKey[:16]).
                byte[] mockTag = new byte[16];
                System.arraycopy(sharedKey, 0, mockTag, 0, Math.min(16, sharedKey.length));
                byte[] ciphertextWithMockTag = new byte[ciphertext.length + mockTag.length];
                System.arraycopy(ciphertext, 0, ciphertextWithMockTag, 0, ciphertext.length);
                System.arraycopy(mockTag, 0, ciphertextWithMockTag, ciphertext.length, mockTag.length);

                Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
                SecretKeySpec keySpec = new SecretKeySpec(sharedKey, "AES");
                GCMParameterSpec gcmSpec = new GCMParameterSpec(128, iv);
                cipher.init(Cipher.DECRYPT_MODE, keySpec, gcmSpec);
                byte[] plaintext = cipher.doFinal(ciphertextWithMockTag);
                return new String(plaintext);
            }
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}


