package scheme.CH.CH_KEF_MH_SDH_DL_AM_2004;

import it.unisa.dia.gas.jpbc.Element;
import utils.Hash;

/*
 * On the Key Exposure Problem in Chameleon Hashes
 * P12. Scheme based on SDH and DL
 */

public class PBC_pairing {
    public static class PublicParam {
        public base.GroupParam.PBC.Symmetry GP;

        public PublicParam(curve.PBC curve) {
            GP = new base.GroupParam.PBC.Symmetry(curve);
        }

        public Element H(Element m) {
            return Hash.H_PBC_1_1(GP.Zr, m);
        }
    }

    public static class PublicKey {
        public Element h, g;
    }

    public static class SecretKey {
        public Element x;
    }

    public static class HashValue {
        public Element h;
    }

    public static class Randomness {
        public Element g_r;
    }

    public void KeyGen(PublicKey pk, SecretKey sk, PublicParam PP) {
        sk.x = PP.GP.GetZrElement();
        pk.g = PP.GP.GetGElement();
        pk.h = pk.g.powZn(sk.x).getImmutable();
    }

    public void Hash(HashValue h, Randomness r, PublicParam PP, PublicKey pk, Element L, Element m) {
        Element r_ = PP.GP.GetZrElement();
        r.g_r = pk.g.powZn(r_).getImmutable();
        h.h = pk.g.powZn(PP.H(m)).mul(pk.g.powZn(PP.H(L)).mul(pk.h).powZn(r_)).getImmutable();
    }

    public boolean Check(HashValue h, Randomness r, PublicParam PP, PublicKey pk, Element L, Element m) {
        Element ghm = pk.g.powZn(PP.H(m));
        Element F = h.h.div(ghm);
        Element geh = pk.g.powZn(PP.H(L)).mul(pk.h);
        return PP.GP.pairing(r.g_r, geh).isEqual(PP.GP.pairing(pk.g, F));
    }

    public void Adapt(Randomness r_p, Randomness r, PublicParam PP, PublicKey pk, SecretKey sk, Element L, Element m, Element m_p) {
        Element e = PP.H(L);
        Element x_e = sk.x.add(e);
        Element H_m_p = PP.H(m_p);
        r_p.g_r = r.g_r.mul(pk.g.powZn(PP.H(m).sub(H_m_p).div(x_e))).getImmutable();
    }
}
