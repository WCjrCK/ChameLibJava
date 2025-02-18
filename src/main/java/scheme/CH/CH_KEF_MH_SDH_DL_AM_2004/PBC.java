package scheme.CH.CH_KEF_MH_SDH_DL_AM_2004;

/*
 * On the Key Exposure Problem in Chameleon Hashes
 * P12. Scheme based on SDH and DL
 */

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import utils.Func;
import utils.Hash;

public class PBC {
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

    public Pairing pairing;

    public Element GetGElement() {
        return pairing.getG1().newRandomElement().getImmutable();
    }

    public Element GetZrElement() {
        return pairing.getZr().newRandomElement().getImmutable();
    }

    public Element H(Element m) {
        return Hash.H_PBC_1_1(pairing.getZr(), m);
    }

    public PBC(curve.PBC curve) {
        pairing = Func.PairingGen(curve);
    }

    public void KeyGen(PublicKey pk, SecretKey sk) {
        sk.x = GetZrElement();
        pk.g = GetGElement();
        pk.h = pk.g.powZn(sk.x).getImmutable();
    }

    public void Hash(HashValue h, Randomness r, PublicKey pk, Element L, Element m) {
        Element r_ = GetZrElement();
        r.g_r = pk.g.powZn(r_).getImmutable();
        h.h = pk.g.powZn(H(m)).mul(pk.g.powZn(H(L)).mul(pk.h).powZn(r_)).getImmutable();
    }

    public boolean Check(HashValue h, Randomness r, PublicKey pk, Element L, Element m) {
        return pairing.pairing(pk.g, h.h.div(pk.g.powZn(H(m)))).isEqual(pairing.pairing(r.g_r, pk.h.mul(pk.g.powZn(H(L)))));
    }

    public void Adapt(Randomness r_p, Randomness r, PublicKey pk, SecretKey sk, Element L, Element m, Element m_p) {
        r_p.g_r = r.g_r.mul(pk.g.powZn(H(m).sub(H(m_p)).div(sk.x.add(H(L))))).getImmutable();
    }
}
