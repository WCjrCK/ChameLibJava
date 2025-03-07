package scheme.CH.CH_KEF_MH_SDH_DL_AM_2004;

import curve.Group;
import it.unisa.dia.gas.jpbc.Element;
import utils.Hash;

/*
 * On the Key Exposure Problem in Chameleon Hashes
 * P12. Scheme based on SDH and DL
 */

public class PBC {
    public static class PublicParam {
        public base.GroupParam.PBC.SingleGroup GP;

        public PublicParam(curve.PBC curve, Group group) {
            GP = new base.GroupParam.PBC.SingleGroup(curve, group);
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
        public base.NIZK.PBC.DH_PAIR_Proof pi;
    }

    public void KeyGen(PublicKey pk, SecretKey sk, PublicParam PP) {
        sk.x = PP.GP.GetZrElement();
        pk.g = PP.GP.GetGElement();
        pk.h = pk.g.powZn(sk.x).getImmutable();
    }

    public void Hash(HashValue h, Randomness r, PublicParam PP, PublicKey pk, Element L, Element m) {
        Element r_ = PP.GP.GetZrElement();
        r.g_r = pk.g.powZn(r_).getImmutable();
        Element geh = pk.g.powZn(PP.H(L)).mul(pk.h);
        Element gehr = geh.powZn(r_);
        h.h = pk.g.powZn(PP.H(m)).mul(gehr).getImmutable();
        r.pi = new base.NIZK.PBC.DH_PAIR_Proof(PP.GP.Zr, r_, pk.g, r.g_r, geh, gehr, PP.GP.ndonr);
    }

    public boolean Check(HashValue h, Randomness r, PublicParam PP, PublicKey pk, Element L, Element m) {
        Element geh = pk.g.powZn(PP.H(L)).mul(pk.h);
        Element gehr = h.h.div(pk.g.powZn(PP.H(m)));
        return r.pi.Check(pk.g, r.g_r, geh, gehr) || r.pi.Check(pk.g, geh, r.g_r, gehr);
    }

    public void Adapt(Randomness r_p, HashValue h, Randomness r, PublicParam PP, PublicKey pk, SecretKey sk, Element L, Element m, Element m_p) {
        Element e = PP.H(L);
        Element x_e = sk.x.add(e);
        Element H_m_p = PP.H(m_p);
        r_p.g_r = r.g_r.mul(pk.g.powZn(PP.H(m).sub(H_m_p).div(x_e))).getImmutable();
        r_p.pi = new base.NIZK.PBC.DH_PAIR_Proof(PP.GP.Zr, x_e, pk.g, pk.g.powZn(e).mul(pk.h), r_p.g_r, h.h.div(pk.g.powZn(H_m_p)), PP.GP.ndonr);
    }
}
