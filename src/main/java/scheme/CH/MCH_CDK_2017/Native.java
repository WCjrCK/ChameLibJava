package scheme.CH.MCH_CDK_2017;

import utils.Func;
import utils.Hash;

import java.math.BigInteger;
import java.util.Random;

/*
 * Chameleon-Hashes with Ephemeral Trapdoors And Applications to Invisible Sanitizable Signatures
 * P42. Construction 5 (Modified Chameleon-Hash)
 */

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

        public void CopyFrom(SecretKey sk) {
            p = sk.p;
            q = sk.q;
            d = sk.d;
        }

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
    public int lambda;

    private static BigInteger H_n(BigInteger n, String m) {
        return Hash.H_String_1_native_1(m).mod(n);
    }

    private static BigInteger getHashValue(Randomness r, PublicKey pk, String m) {
        return H_n(pk.n, m).multiply(r.r.modPow(pk.e, pk.n)).mod(pk.n);
    }

    public Native(int l) {
        lambda = l;
    }

    public void KeyGen(PublicKey pk, SecretKey sk) {
        AE.RSA.Native.PublicKey pk_rsa = new AE.RSA.Native.PublicKey();
        AE.RSA.Native.SecretKey sk_rsa = new AE.RSA.Native.SecretKey();
        AE.RSA.Native.KeyGen(pk_rsa, sk_rsa, 2 * lambda + 1, lambda);
        pk.CopyFrom(pk_rsa);
        sk.CopyFrom(sk_rsa);
    }

    public void Hash(HashValue h, Randomness r, PublicKey pk, String m) {
        r.r = Func.getZq(rand, pk.n);
        h.h = getHashValue(r, pk, m);
    }

    public boolean Check(HashValue h, Randomness r, PublicKey pk, String m) {
        return h.h.compareTo(getHashValue(r, pk, m)) == 0;
    }

    public void Adapt(Randomness r_p, Randomness r, PublicKey pk, SecretKey sk, String m, String m_p) {
        r_p.r = getHashValue(r, pk, m).multiply(H_n(pk.n, m_p).modInverse(pk.n)).modPow(sk.d, pk.n);
    }
}
