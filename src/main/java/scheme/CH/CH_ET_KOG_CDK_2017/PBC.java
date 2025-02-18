package scheme.CH.CH_ET_KOG_CDK_2017;

import curve.Group;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Field;
import it.unisa.dia.gas.jpbc.Pairing;
import utils.Func;
import utils.Hash;

import java.math.BigInteger;

/*
 * Chameleon-Hashes with Ephemeral Trapdoors And Applications to Invisible Sanitizable Signatures
 * P12. Construction 2 (CHET in Known-Order Groups)
 */

@SuppressWarnings("rawtypes")
public class PBC {
    @SuppressWarnings("BooleanMethodIsAlwaysInverted")
    public static class NIZKPoK {
        public static class Proof {
            public Element z, R;
        }

        Field Zr;

        private Element H(Element m1, Element m2) {
            return Hash.H_PBC_2_1(Zr, m1, m2);
        }

        public NIZKPoK(Field Zr) {
            this.Zr = Zr;
        }

        public void GenProof(Proof pi, Element g, Element pk, Element sk) {
            Element r = Zr.newRandomElement().getImmutable();
            pi.R = g.powZn(r).getImmutable();
            pi.z = r.add(H(pk, pi.R).mul(sk)).getImmutable();
        }

        public boolean Verify(Proof pi, Element g, Element pk) {
            return g.powZn(pi.z).isEqual(pi.R.mul(pk.powZn(H(pk, pi.R))));
        }
    }

    public static class PublicParam {
        public Field G;
        public Element g;
        public int lambda;
    }

    public static class PublicKey {
        public Element h;
        public NIZKPoK.Proof pi_pk = new NIZKPoK.Proof();
        public AE.RSA.Native.PublicKey pk_enc = new AE.RSA.Native.PublicKey();
    }

    public static class SecretKey {
        public Element x;
        public AE.RSA.Native.SecretKey sk_enc = new AE.RSA.Native.SecretKey();
    }

    public static class HashValue {
        public Element b, h_p;
        public NIZKPoK.Proof pi_t = new NIZKPoK.Proof();
    }

    public static class Randomness {
        public Element p;
        public BigInteger C;
        public NIZKPoK.Proof pi_p = new NIZKPoK.Proof();
    }

    public static class ETrapdoor {
        public Element etd;
    }

    NIZKPoK nizkpok;
    Field Zr;

    private Element H(Element m1) {
        return Hash.H_PBC_1_1(Zr, m1);
    }

    public Element getZrElement() {
        return Zr.newRandomElement().getImmutable();
    }

    public PBC(PublicParam pp, curve.PBC curve, Group group, int lambda) {
        Pairing pairing = Func.PairingGen(curve);
        Zr = pairing.getZr();
        nizkpok = new NIZKPoK(Zr);
        pp.G = Func.GetPBCField(pairing, group);
        pp.g = pp.G.newRandomElement().getImmutable();
        pp.lambda = lambda;
    }

    public void KeyGen(PublicKey pk, SecretKey sk, PublicParam pp) {
        sk.x = getZrElement();
        pk.h = pp.g.powZn(sk.x).getImmutable();
        nizkpok.GenProof(pk.pi_pk, pp.g, pk.h, sk.x);
        AE.RSA.Native.KeyGen(pk.pk_enc, sk.sk_enc, pp.lambda, pp.lambda);
    }

    public void Hash(HashValue H, Randomness R, ETrapdoor etd, PublicParam pp, PublicKey pk, Element m) {
        if(!nizkpok.Verify(pk.pi_pk, pp.g, pk.h)) throw new RuntimeException("not valid proof");
        Element r = getZrElement();
        etd.etd = getZrElement();
        H.h_p = pp.g.powZn(etd.etd).getImmutable();
        nizkpok.GenProof(H.pi_t, pp.g, H.h_p, etd.etd);
        R.C = AE.RSA.Native.Encrypt(r.toBigInteger(), pk.pk_enc);
        Element a = H(m);
        R.p = pk.h.powZn(r).getImmutable();
        nizkpok.GenProof(R.pi_p, pk.h, R.p, r);
        H.b = R.p.mul(H.h_p.powZn(a)).getImmutable();
    }

    public boolean Check(HashValue H, Randomness R, PublicParam pp, PublicKey pk, Element m) {
        if(!nizkpok.Verify(R.pi_p, pk.h, R.p) || !nizkpok.Verify(H.pi_t, pp.g, H.h_p) || !nizkpok.Verify(pk.pi_pk, pp.g, pk.h))
            throw new RuntimeException("not valid proof");
        Element a = H(m);
        return H.b.isEqual(R.p.mul(H.h_p.powZn(a)));
    }

    public void Adapt(Randomness R_p, HashValue H, Randomness R, ETrapdoor etd, PublicParam pp, PublicKey pk, SecretKey sk, Element m, Element m_p) {
        if(!Check(H, R, pp, pk, m)) throw new RuntimeException("not valid hash");
        Element r = Zr.newElement(AE.RSA.Native.Decrypt(R.C, pk.pk_enc, sk.sk_enc)).getImmutable();
        if(!H.h_p.isEqual(pp.g.powZn(etd.etd))) throw new RuntimeException("not valid hash");
        Element a = H(m);
        Element a_p = H(m_p);
        if(!R.p.isEqual(pp.g.powZn(r.mul(sk.x)))) throw new RuntimeException("not valid hash");
        if(a.isEqual(a_p)) {
            R_p.C = R.C;
            R_p.p = R.p;
            R_p.pi_p = R.pi_p;
            return;
        }
        Element r_p = r.add(a.sub(a_p).mul(etd.etd).div(sk.x)).getImmutable();
        R_p.p = pk.h.powZn(r_p).getImmutable();
        R_p.C = AE.RSA.Native.Encrypt(r_p.toBigInteger(), pk.pk_enc);
        nizkpok.GenProof(R_p.pi_p, pk.h, R_p.p, r_p);
    }
}
