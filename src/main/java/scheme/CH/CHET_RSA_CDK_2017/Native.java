package scheme.CH.CHET_RSA_CDK_2017;

import utils.Func;
import utils.Hash;

import java.math.BigInteger;
import java.util.Random;

/*
 * Chameleon-Hashes with Ephemeral Trapdoors And Applications to Invisible Sanitizable Signatures
 * P44. Construction 6 (CHET from RSA-like Assumptions)
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
        public BigInteger p, q;

        public void CopyFrom(AE.RSA.Native.SecretKey sk) {
            p = sk.p;
            q = sk.q;
        }
    }

    public static class HashValue {
        public BigInteger h, n_p;
    }

    public static class Randomness {
        public BigInteger r;
    }

    public static class ETrapdoor {
        public BigInteger p_p, q_p;

        public void CopyFrom(AE.RSA.Native.SecretKey sk) {
            p_p = sk.p;
            q_p = sk.q;
        }
    }

    Random rand = new Random();
    int lambda;

    private static BigInteger H_n_n_p(BigInteger n_n_p, BigInteger m) {
        return Hash.H_native_1_1(m).mod(n_n_p);
    }

    public Native(int lambda) {
        this.lambda = lambda;
    }

    public void KeyGen(PublicKey pk, SecretKey sk) {
        AE.RSA.Native.PublicKey pk_rsa = new AE.RSA.Native.PublicKey();
        AE.RSA.Native.SecretKey sk_rsa = new AE.RSA.Native.SecretKey();
        AE.RSA.Native.KeyGen(pk_rsa, sk_rsa, 6 * lambda + 1, lambda);
        pk.CopyFrom(pk_rsa);
        sk.CopyFrom(sk_rsa);
    }

    public void Hash(HashValue H, Randomness R, ETrapdoor etd, PublicKey pk, BigInteger m) {
        AE.RSA.Native.PublicKey pk_rsa = new AE.RSA.Native.PublicKey();
        AE.RSA.Native.SecretKey sk_rsa = new AE.RSA.Native.SecretKey();
        AE.RSA.Native.KeyGen(pk_rsa, sk_rsa, pk.n, pk.e, lambda);
        H.n_p = pk_rsa.N;
        etd.CopyFrom(sk_rsa);
        BigInteger n_n_p = pk.n.multiply(H.n_p);
        R.r = Func.getZq(rand, n_n_p);
        H.h = H_n_n_p(n_n_p, m).multiply(R.r.modPow(pk.e, n_n_p)).mod(n_n_p);
    }

    public boolean Check(HashValue H, Randomness R, PublicKey pk, BigInteger m) {
        BigInteger n_n_p = pk.n.multiply(H.n_p);
        if(R.r.compareTo(BigInteger.ONE) < 0 || R.r.compareTo(n_n_p) >= 0) throw new RuntimeException("illegal randomness");
        return H.h.compareTo(H_n_n_p(n_n_p, m).multiply(R.r.modPow(pk.e, n_n_p)).mod(n_n_p)) == 0;
    }

    public void Adapt(Randomness R_p, HashValue H, Randomness R, ETrapdoor etd, PublicKey pk, SecretKey sk, BigInteger m, BigInteger m_p) {
        if(H.n_p.compareTo(etd.p_p.multiply(etd.q_p)) != 0) throw new RuntimeException("illegal etd");
        if(!Check(H, R, pk, m)) throw new RuntimeException("illegal hash");
        BigInteger n_n_p = pk.n.multiply(H.n_p);
        BigInteger d = pk.e.modInverse(Func.phi(etd.p_p, etd.q_p).multiply(Func.phi(sk.p, sk.q)));
        R_p.r = H.h.multiply(H_n_n_p(n_n_p, m_p).modInverse(n_n_p)).modPow(d, n_n_p);
    }
}
