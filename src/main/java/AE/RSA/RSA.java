package AE.RSA;

import java.math.BigInteger;
import java.util.Random;

import static utils.Func.phi;

public class RSA {
    static public void KeyGen(PublicKey pk, SecretKey sk) {
        Random rand = new Random();
        pk.e = new BigInteger("65537");
        sk.p = BigInteger.probablePrime(1024, rand);
        sk.q = BigInteger.probablePrime(1024, rand);
        BigInteger phi = phi(sk.p, sk.q);
        while (phi.gcd(pk.e).compareTo(BigInteger.ONE) != 0) {
            sk.p = BigInteger.probablePrime(1024, rand);
            sk.q = BigInteger.probablePrime(1024, rand);
            phi = phi(sk.p, sk.q);
        }
        pk.N = sk.p.multiply(sk.q);
        sk.d = pk.e.modInverse(phi);
    }

    static public void KeyGen(PublicKey pk, SecretKey sk, int e_bit, int p_bit) {
        Random rand = new Random();
        pk.e = BigInteger.probablePrime(e_bit, rand);
        sk.p = BigInteger.probablePrime(p_bit, rand);
        sk.q = BigInteger.probablePrime(p_bit, rand);
        BigInteger phi = phi(sk.p, sk.q);
        while (phi.gcd(pk.e).compareTo(BigInteger.ONE) != 0) {
            sk.p = BigInteger.probablePrime(p_bit, rand);
            sk.q = BigInteger.probablePrime(p_bit, rand);
            phi = phi(sk.p, sk.q);
        }
        pk.N = sk.p.multiply(sk.q);
        sk.d = pk.e.modInverse(phi);
    }

    static public BigInteger Encrypt(BigInteger pt, PublicKey pk) {
        return pt.modPow(pk.e, pk.N);
    }

    static public BigInteger Decrypt(BigInteger ct, PublicKey pk, SecretKey sk) {
        return ct.modPow(sk.d, pk.N);
    }
}
