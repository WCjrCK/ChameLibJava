package scheme.CH.CH_ET_BC_CDK_2017;

/*
 * Chameleon-Hashes with Ephemeral Trapdoors And Applications to Invisible Sanitizable Signatures
 * P11. Black-Box Construction: Bootstrapping
 */

public class Native {
    public static class CH_RSA extends scheme.CH.MCH_CDK_2017.Native {
        public CH_RSA(int lambda) {
            super(lambda);
        }
    }

    public static class PublicKey {
        public CH_RSA.PublicKey pk_ch_1 = new CH_RSA.PublicKey();
    }

    public static class SecretKey {
        public CH_RSA.SecretKey sk_ch_1 = new CH_RSA.SecretKey();

        public void CopyFrom(SecretKey sk) {
            sk_ch_1.CopyFrom(sk.sk_ch_1);
        }
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

    public CH_RSA CH;

    public Native(int lambda) {
        CH = new CH_RSA(lambda);
    }

    public void KeyGen(PublicKey pk, SecretKey sk) {
        CH.KeyGen(pk.pk_ch_1, sk.sk_ch_1);
    }

    public void Hash(HashValue h, Randomness r, ETrapdoor etd, PublicKey pk, String m) {
        CH.KeyGen(h.pk_ch_2, etd.sk_ch_2);
        m = String.format("%s|%s|%s", m, pk.pk_ch_1.n, h.pk_ch_2.n);
        CH.Hash(h.h_1, r.r_1, pk.pk_ch_1, m + "1");
        CH.Hash(h.h_2, r.r_2, h.pk_ch_2, m + "2");
    }

    public boolean Check(HashValue h, Randomness r, PublicKey pk, String m) {
        m = String.format("%s|%s|%s", m, pk.pk_ch_1.n, h.pk_ch_2.n);
        return CH.Check(h.h_1, r.r_1, pk.pk_ch_1, m + "1") && CH.Check(h.h_2, r.r_2, h.pk_ch_2, m + "2");
    }

    public void Adapt(Randomness r_p, HashValue h, Randomness r, ETrapdoor etd, PublicKey pk, SecretKey sk, String m, String m_p) {
        if(!Check(h, r, pk, m)) throw new RuntimeException("illegal hash");
        m = String.format("%s|%s|%s", m, pk.pk_ch_1.n, h.pk_ch_2.n);
        m_p = String.format("%s|%s|%s", m_p, pk.pk_ch_1.n, h.pk_ch_2.n);
        CH.Adapt(r_p.r_1, r.r_1, pk.pk_ch_1, sk.sk_ch_1, m + "1", m_p + "1");
        CH.Adapt(r_p.r_2, r.r_2, h.pk_ch_2, etd.sk_ch_2, m + "2", m_p + "2");
    }
}
