package AE.RSA;

import java.math.BigInteger;
import java.util.Random;

import static utils.func.phi;
import static utils.func.gcd;

public class RSA {
    static public void KeyGen(PublicKey pk, SecretKey sk) {
        Random rand = new Random();
        pk.e = new BigInteger("65537");
        BigInteger p = BigInteger.probablePrime(1024, rand);
        BigInteger q = BigInteger.probablePrime(1024, rand);
        BigInteger phi = phi(p, q);
        while (gcd(phi, pk.e).compareTo(BigInteger.ONE) != 0) {
            p = BigInteger.probablePrime(1024, rand);
            q = BigInteger.probablePrime(1024, rand);
            phi = phi(p, q);
        }
        pk.N = p.multiply(q);
        sk.d = pk.e.modInverse(phi);
    }

    static public BigInteger Encrypt(BigInteger pt, PublicKey pk) {
        return pt.modPow(pk.e, pk.N);
    }

    static public BigInteger Decrypt(BigInteger ct, PublicKey pk, SecretKey sk) {
        return ct.modPow(sk.d, pk.N);
    }
}
