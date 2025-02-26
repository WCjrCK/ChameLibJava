package scheme.CH.CH_ET_KOG_CDK_2017;

import curve.Group;
import it.unisa.dia.gas.jpbc.Element;
import utils.Hash;

import java.math.BigInteger;

/*
 * Chameleon-Hashes with Ephemeral Trapdoors And Applications to Invisible Sanitizable Signatures
 * P12. Construction 2 (CHET in Known-Order Groups)
 */

public class PBC {
    public static class PublicParam {
        public base.GroupParam.PBC.SingleGroup GP;
        public Element g;
        public int lambda;

        public PublicParam(curve.PBC curve, Group group, int lambda) {
            GP = new base.GroupParam.PBC.SingleGroup(curve, group);
            g = GP.GetGElement();
            this.lambda = lambda;
        }

        public Element H(Element m1) {
            return Hash.H_PBC_1_1(GP.Zr, m1);
        }
    }

    public static class PublicKey {
        public Element h;
        public base.NIZK.PBC.DL_Proof pi_pk;
        public AE.RSA.Native.PublicKey pk_enc = new AE.RSA.Native.PublicKey();
    }

    public static class SecretKey {
        public Element x;
        public AE.RSA.Native.SecretKey sk_enc = new AE.RSA.Native.SecretKey();
    }

    public static class HashValue {
        public Element b, h_p;
        public base.NIZK.PBC.DL_Proof pi_t;
    }

    public static class Randomness {
        public Element p;
        public BigInteger C;
        public base.NIZK.PBC.DL_Proof pi_p;
    }

    public static class ETrapdoor {
        public Element etd;
    }

    public void KeyGen(PublicKey pk, SecretKey sk, PublicParam pp) {
        sk.x = pp.GP.GetZrElement();
        pk.h = pp.g.powZn(sk.x).getImmutable();
        pk.pi_pk = new base.NIZK.PBC.DL_Proof(pp.GP.Zr, sk.x, pp.g, pk.h);
        AE.RSA.Native.KeyGen(pk.pk_enc, sk.sk_enc, pp.lambda, pp.lambda);
    }

    public void Hash(HashValue H, Randomness R, ETrapdoor etd, PublicParam pp, PublicKey pk, Element m) {
        if(!pk.pi_pk.Check(pp.g, pk.h)) throw new RuntimeException("not valid proof");
        Element r = pp.GP.GetZrElement();
        etd.etd = pp.GP.GetZrElement();
        H.h_p = pp.g.powZn(etd.etd).getImmutable();
        H.pi_t = new base.NIZK.PBC.DL_Proof(pp.GP.Zr, etd.etd, pp.g, H.h_p);
        R.C = AE.RSA.Native.Encrypt(r.toBigInteger(), pk.pk_enc);
        Element a = pp.H(m);
        R.p = pk.h.powZn(r).getImmutable();
        R.pi_p = new base.NIZK.PBC.DL_Proof(pp.GP.Zr, r, pk.h, R.p);
        H.b = R.p.mul(H.h_p.powZn(a)).getImmutable();
    }

    public boolean Check(HashValue H, Randomness R, PublicParam pp, PublicKey pk, Element m) {
        if(!R.pi_p.Check(pk.h, R.p) || !H.pi_t.Check(pp.g, H.h_p) || !pk.pi_pk.Check(pp.g, pk.h))
            throw new RuntimeException("not valid proof");
        Element a = pp.H(m);
        return H.b.isEqual(R.p.mul(H.h_p.powZn(a)));
    }

    public void Adapt(Randomness R_p, HashValue H, Randomness R, ETrapdoor etd, PublicParam pp, PublicKey pk, SecretKey sk, Element m, Element m_p) {
        if(!Check(H, R, pp, pk, m)) throw new RuntimeException("not valid hash");
        Element r = pp.GP.Zr.newElement(AE.RSA.Native.Decrypt(R.C, pk.pk_enc, sk.sk_enc)).getImmutable();
        if(!H.h_p.isEqual(pp.g.powZn(etd.etd))) throw new RuntimeException("not valid hash");
        Element a = pp.H(m);
        Element a_p = pp.H(m_p);
        if(!R.p.isEqual(pp.g.powZn(r.mul(sk.x)))) throw new RuntimeException("not valid hash");
        if(a.isEqual(a_p)) {
            R_p.C = R.C;
            R_p.p = R.p;
            R_p.pi_p.CopyFrom(R.pi_p);
            return;
        }
        Element r_p = r.add(a.sub(a_p).mul(etd.etd).div(sk.x)).getImmutable();
        R_p.p = pk.h.powZn(r_p).getImmutable();
        R_p.C = AE.RSA.Native.Encrypt(r_p.toBigInteger(), pk.pk_enc);
        R_p.pi_p = new base.NIZK.PBC.DL_Proof(pp.GP.Zr, r_p, pk.h, R_p.p);
    }
}
