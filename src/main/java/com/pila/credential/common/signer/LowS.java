package com.pila.credential.common.signer;

import java.math.BigInteger;

/** Go signer.NormalizeLowS. */
public final class LowS {
    private LowS() {
    }

    /**
     * Returns s if s &lt;= n/2, otherwise n-s, so signatures are accepted by verifiers that reject high-S.
     *
     * @param curveOrder the order n of the curve
     */
    public static BigInteger normalize(BigInteger curveOrder, BigInteger s) {
        BigInteger halfN = curveOrder.shiftRight(1);
        return s.compareTo(halfN) > 0 ? curveOrder.subtract(s) : s;
    }
}
