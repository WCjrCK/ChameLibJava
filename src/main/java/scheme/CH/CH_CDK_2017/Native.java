package scheme.CH.CH_CDK_2017;

/*
 * Chameleon-Hashes with Ephemeral Trapdoors And Applications to Invisible Sanitizable Signatures
 * P41. Construction 4 (Chameleon-Hash)
 */

import utils.Func;
import utils.Hash;

import java.math.BigInteger;
import java.util.Random;

public class Native {
    public static class PublicKey {
        public BigInteger n, e;

        public void CopyFrom(AE.RSA.Native.PublicKey pk) {
            n = pk.N;
            e = pk.e;
        }
    }

    public static class SecretKey {
        public BigInteger p, q, d;

        public void CopyFrom(AE.RSA.Native.SecretKey sk) {
            p = sk.p;
            q = sk.q;
            d = sk.d;
        }
    }

    public static class HashValue {
        public BigInteger h;
    }

    public static class Randomness {
        public BigInteger r;
    }

    Random rand = new Random();
    int lambda;

    private static BigInteger H_n(BigInteger n, BigInteger m1, BigInteger m2) {
        return Hash.H_native_2_1(m1, m2).mod(n);
    }

    private static BigInteger getHashValue(Randomness r, PublicKey pk, BigInteger tau, BigInteger m) {
        return H_n(pk.n, tau, m).multiply(r.r.modPow(pk.e, pk.n)).mod(pk.n);
    }

    public Native(int l) {
        lambda = l;
    }

    public void KeyGen(PublicKey pk, SecretKey sk) {
        AE.RSA.Native.PublicKey pk_rsa = new AE.RSA.Native.PublicKey();
        AE.RSA.Native.SecretKey sk_rsa = new AE.RSA.Native.SecretKey();
        AE.RSA.Native.KeyGen(pk_rsa, sk_rsa, lambda, lambda);
        pk.CopyFrom(pk_rsa);
        sk.CopyFrom(sk_rsa);
    }

    public void Hash(HashValue h, Randomness r, PublicKey pk, BigInteger tau, BigInteger m) {
        r.r = Func.getZq(rand, pk.n);
        h.h = getHashValue(r, pk, tau, m);
    }

    public boolean Check(HashValue h, Randomness r, PublicKey pk, BigInteger tau, BigInteger m) {
        return h.h.compareTo(getHashValue(r, pk, tau, m)) == 0;
    }

    public void Adapt(Randomness r_p, Randomness r, PublicKey pk, SecretKey sk, BigInteger tau, BigInteger m, BigInteger tau_p, BigInteger m_p) {
        r_p.r = getHashValue(r, pk, tau, m).multiply(H_n(pk.n, tau_p, m_p).modInverse(pk.n)).modPow(sk.d, pk.n);
    }
}
