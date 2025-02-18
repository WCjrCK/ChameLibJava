package scheme.CH.CH_ET_BC_CDK_2017;

/*
 * Chameleon-Hashes with Ephemeral Trapdoors And Applications to Invisible Sanitizable Signatures
 * P11. Black-Box Construction: Bootstrapping
 */

import utils.Func;
import utils.Hash;

import java.math.BigInteger;
import java.util.Random;

public class Native {
    private static class CH_RSA {
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

        private static BigInteger H_n(BigInteger n, BigInteger m) {
            return Hash.H_native_1_1(m).mod(n);
        }

        private static BigInteger getHashValue(Randomness r, PublicKey pk, BigInteger m) {
            return H_n(pk.n, m).multiply(r.r.modPow(pk.e, pk.n)).mod(pk.n);
        }

        public CH_RSA(int l) {
            lambda = l;
        }

        public void KeyGen(PublicKey pk, SecretKey sk) {
            AE.RSA.Native.PublicKey pk_rsa = new AE.RSA.Native.PublicKey();
            AE.RSA.Native.SecretKey sk_rsa = new AE.RSA.Native.SecretKey();
            AE.RSA.Native.KeyGen(pk_rsa, sk_rsa, lambda, lambda);
            pk.CopyFrom(pk_rsa);
            sk.CopyFrom(sk_rsa);
        }

        public void Hash(HashValue h, Randomness r, PublicKey pk, BigInteger m) {
            r.r = Func.getZq(rand, pk.n);
            h.h = getHashValue(r, pk, m);
        }

        public boolean Check(HashValue h, Randomness r, PublicKey pk, BigInteger m) {
            return h.h.compareTo(getHashValue(r, pk, m)) == 0;
        }

        public void Adapt(Randomness r_p, Randomness r, PublicKey pk, SecretKey sk, BigInteger m, BigInteger m_p) {
            r_p.r = getHashValue(r, pk, m).multiply(H_n(pk.n, m_p).modInverse(pk.n)).modPow(sk.d, pk.n);
        }
    }

    public static class PublicKey {
        public CH_RSA.PublicKey pk_ch_1 = new CH_RSA.PublicKey();
    }

    public static class SecretKey {
        public CH_RSA.SecretKey sk_ch_1 = new CH_RSA.SecretKey();
    }

    public static class HashValue {
        public CH_RSA.HashValue h_1 = new CH_RSA.HashValue(), h_2 = new CH_RSA.HashValue();
        public CH_RSA.PublicKey pk_ch_2 = new CH_RSA.PublicKey();
    }

    public static class Randomness {
        public CH_RSA.Randomness r_1 = new CH_RSA.Randomness(), r_2 = new CH_RSA.Randomness();
    }

    public static class ETrapdoor {
        public CH_RSA.SecretKey sk_ch_2 = new CH_RSA.SecretKey();
    }

    CH_RSA CH;

    public Native(int lambda) {
        CH = new CH_RSA(lambda);
    }

    public void KeyGen(PublicKey pk, SecretKey sk) {
        CH.KeyGen(pk.pk_ch_1, sk.sk_ch_1);
    }

    public void Hash(HashValue h, Randomness r, ETrapdoor etd, PublicKey pk, BigInteger m) {
        CH.KeyGen(h.pk_ch_2, etd.sk_ch_2);
        CH.Hash(h.h_1, r.r_1, pk.pk_ch_1, m);
        CH.Hash(h.h_2, r.r_2, h.pk_ch_2, m);
    }

    public boolean Check(HashValue h, Randomness r, PublicKey pk, BigInteger m) {
        return CH.Check(h.h_1, r.r_1, pk.pk_ch_1, m) && CH.Check(h.h_2, r.r_2, h.pk_ch_2, m);
    }

    public void Adapt(Randomness r_p, HashValue h, Randomness r, ETrapdoor etd, PublicKey pk, SecretKey sk, BigInteger m, BigInteger m_p) {
        if(!Check(h, r, pk, m)) throw new RuntimeException("illegal hash");
        CH.Adapt(r_p.r_1, r.r_1, pk.pk_ch_1, sk.sk_ch_1, m, m_p);
        CH.Adapt(r_p.r_2, r.r_2, h.pk_ch_2, etd.sk_ch_2, m, m_p);
    }
}
