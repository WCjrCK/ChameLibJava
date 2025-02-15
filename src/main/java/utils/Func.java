package utils;

import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.math.BigInteger;
import java.util.Random;

public class Func {
    public static void InitialLib() {
        System.loadLibrary("mcljava");
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

    public static BigInteger lcm(BigInteger a, BigInteger b) {
        return a.multiply(b).divide(gcd(a, b));
    }

    public static BigInteger getZq(Random rand, BigInteger q) {
        BigInteger res;
        do {
            res = new BigInteger(q.bitLength(), rand).mod(q);
        } while (res.compareTo(BigInteger.ZERO) <= 0 || res.compareTo(q) >= 0);
        return res;
    }
}
