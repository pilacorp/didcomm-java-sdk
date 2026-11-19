package com.pila.credential.common.ecdsasd;

import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBOREncodeOptions;
import com.upokecenter.cbor.CBORType;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

public final class ProofValue {

    static final byte[] BASE_PROOF_HEADER = new byte[] { (byte) 0xd9, 0x5d, 0x00 };
    static final byte[] DERIVED_PROOF_HEADER = new byte[] { (byte) 0xd9, 0x5d, 0x01 };

    private ProofValue() {
    }

    public static final class SpecBaseProof {
        public byte[] baseSignature;
        public byte[] publicKey;
        public byte[] hmacKey;
        public List<byte[]> signatures;
        public List<String> mandatoryPointers;
    }

    public static final class SpecDerivedProof {
        public byte[] baseSignature;
        public byte[] publicKey;
        public List<byte[]> signatures;
        public Map<String, String> labelMap;
        public List<Integer> mandatoryIndexes;
    }

    public static String serializeBaseProofValue(SpecBaseProof p) throws Exception {
        List<String> mandatory = p.mandatoryPointers != null ? p.mandatoryPointers : List.of();
        CBORObject payload = CBORObject.NewArray();
        payload.Add(CBORObject.FromObject(p.baseSignature));
        payload.Add(CBORObject.FromObject(p.publicKey));
        payload.Add(CBORObject.FromObject(p.hmacKey));
        CBORObject sigs = CBORObject.NewArray();
        for (byte[] sig : p.signatures) {
            sigs.Add(CBORObject.FromObject(sig));
        }
        payload.Add(sigs);
        CBORObject mptrs = CBORObject.NewArray();
        for (String ptr : mandatory) {
            mptrs.Add(CBORObject.FromObject(ptr));
        }
        payload.Add(mptrs);
        return multibaseProofValue(BASE_PROOF_HEADER, payload.EncodeToBytes(CBOREncodeOptions.Default));
    }

    public static SpecBaseProof parseBaseProofValue(String proofValue) throws Exception {
        byte[] raw = decodeProofValue(proofValue, BASE_PROOF_HEADER);
        CBORObject arr = CBORObject.DecodeFromBytes(raw);
        if (arr.getType() != CBORType.Array || arr.size() != 5) {
            throw new Exception("ecdsasd: base proof value: want 5 elements, got " + arr.size());
        }
        SpecBaseProof out = new SpecBaseProof();
        out.baseSignature = arr.get(0).GetByteString();
        out.publicKey = arr.get(1).GetByteString();
        out.hmacKey = arr.get(2).GetByteString();
        out.signatures = new ArrayList<>();
        for (CBORObject item : arr.get(3).getValues()) {
            out.signatures.add(item.GetByteString());
        }
        out.mandatoryPointers = new ArrayList<>();
        for (CBORObject item : arr.get(4).getValues()) {
            out.mandatoryPointers.add(item.AsString());
        }
        return out;
    }

    public static String serializeDisclosureProofValue(SpecDerivedProof p) throws Exception {
        CBORObject compressed = compressLabelMap(p.labelMap);
        CBORObject mIdx = CBORObject.NewArray();
        for (Integer n : p.mandatoryIndexes) {
            mIdx.Add(CBORObject.FromObject(n));
        }
        CBORObject payload = CBORObject.NewArray();
        payload.Add(CBORObject.FromObject(p.baseSignature));
        payload.Add(CBORObject.FromObject(p.publicKey));
        CBORObject sigs = CBORObject.NewArray();
        for (byte[] sig : p.signatures) {
            sigs.Add(CBORObject.FromObject(sig));
        }
        payload.Add(sigs);
        payload.Add(compressed);
        payload.Add(mIdx);
        return multibaseProofValue(DERIVED_PROOF_HEADER, payload.EncodeToBytes(CBOREncodeOptions.Default));
    }

    public static SpecDerivedProof parseDisclosureProofValue(String proofValue) throws Exception {
        byte[] raw = decodeProofValue(proofValue, DERIVED_PROOF_HEADER);
        CBORObject arr = CBORObject.DecodeFromBytes(raw);
        if (arr.getType() != CBORType.Array || arr.size() != 5) {
            throw new Exception("ecdsasd: derived proof value: want 5 elements, got " + arr.size());
        }
        SpecDerivedProof out = new SpecDerivedProof();
        out.baseSignature = arr.get(0).GetByteString();
        out.publicKey = arr.get(1).GetByteString();
        out.signatures = new ArrayList<>();
        for (CBORObject item : arr.get(2).getValues()) {
            out.signatures.add(item.GetByteString());
        }
        out.labelMap = decompressLabelMap(arr.get(3));
        out.mandatoryIndexes = new ArrayList<>();
        for (CBORObject item : arr.get(4).getValues()) {
            out.mandatoryIndexes.add(item.AsInt32Value());
        }
        return out;
    }

    static CBORObject compressLabelMap(Map<String, String> labelMap) throws Exception {
        CBORObject out = CBORObject.NewMap();
        for (Map.Entry<String, String> e : labelMap.entrySet()) {
            String k = e.getKey();
            if (!k.startsWith("c14n")) {
                throw new Exception("ecdsasd: label map key " + k);
            }
            long num = Long.parseLong(k.substring(4));
            byte[] b = Base64.getUrlDecoder().decode(e.getValue().substring(1));
            out.Add(CBORObject.FromObject(num), CBORObject.FromObject(b));
        }
        return out;
    }

    static Map<String, String> decompressLabelMap(CBORObject compressed) throws Exception {
        Map<String, String> out = new TreeMap<>();
        for (CBORObject key : compressed.getKeys()) {
            long num = key.AsInt64Value();
            byte[] b = compressed.get(key).GetByteString();
            out.put("c14n" + num, "u" + Base64.getUrlEncoder().withoutPadding().encodeToString(b));
        }
        return out;
    }

    static String multibaseProofValue(byte[] header, byte[] payload) {
        byte[] buf = new byte[header.length + payload.length];
        System.arraycopy(header, 0, buf, 0, header.length);
        System.arraycopy(payload, 0, buf, header.length, payload.length);
        return "u" + Base64.getUrlEncoder().withoutPadding().encodeToString(buf);
    }

    static byte[] decodeProofValue(String proofValue, byte[] header) throws Exception {
        if (proofValue == null || proofValue.isEmpty() || proofValue.charAt(0) != 'u') {
            throw new Exception("ecdsasd: proof value must be base64url-no-pad multibase ('u')");
        }
        byte[] raw = Base64.getUrlDecoder().decode(proofValue.substring(1));
        if (raw.length < header.length || !Arrays.equals(Arrays.copyOf(raw, header.length), header)) {
            throw new Exception("ecdsasd: proof value has wrong header");
        }
        return Arrays.copyOfRange(raw, header.length, raw.length);
    }
}
