package utils;

import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.math.BigInteger;

public class func {
    public static void InitialLib() {
        System.loadLibrary("mcljava");
        System.loadLibrary("gmp4j");
        System.loadLibrary("gmp");
        PairingFactory.getInstance().setUsePBCWhenPossible(true);
    }

    public static BigInteger phi(BigInteger p, BigInteger q) {
        return p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));
    }

    public static BigInteger gcd(BigInteger a, BigInteger b) {
        if (b.compareTo(BigInteger.ZERO) == 0) {
            return a;
        }
        return gcd(b, a.mod(b));
    }
}
