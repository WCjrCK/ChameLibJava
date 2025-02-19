package scheme.CH.CH_KEF_CZK_2004;

import curve.Group;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Field;
import it.unisa.dia.gas.jpbc.Pairing;
import utils.Func;
import utils.Hash;

/*
 * Chameleon Hashing without Key Exposure
 * P7. 3.3.1 The scheme
 */

@SuppressWarnings("rawtypes")
public class PBC {
    public static class PublicParam {
        Field G;
        Element g;

        public Element GetGElement() {
            return G.newRandomElement().getImmutable();
        }

        public Element H(String m) {
            return Hash.H_String_1_PBC_1(G, m);
        }
    }

    public static class PublicKey {
        public Element y;
    }

    public static class SecretKey {
        public Element x;
    }

    public static class HashValue {
        public Element h;
    }

    public static class Randomness {
        public Element g_a, y_a;
    }

    Field Zr;

    private static Element getHashValue(Randomness R, PublicParam SP, Element I, Element m) {
        return SP.g.mul(I).powZn(m).mul(R.y_a).getImmutable();
    }

    public Element GetZrElement() {
        return Zr.newRandomElement().getImmutable();
    }

    public void SetUp(PublicParam SP, curve.PBC curve, Group group) {
        Pairing pairing = Func.PairingGen(curve);
        SP.G = Func.GetPBCField(pairing, group);
        SP.g = SP.GetGElement();
        Zr = pairing.getZr();
    }

    public void KeyGen(PublicKey pk, SecretKey sk, PublicParam SP) {
        sk.x = GetZrElement();
        pk.y = SP.g.powZn(sk.x).getImmutable();
    }

    public void Hash(HashValue H, Randomness R, PublicParam SP, PublicKey pk, Element I, Element m) {
        Element a = GetZrElement();
        R.g_a = SP.g.powZn(a).getImmutable();
        R.y_a = pk.y.powZn(a).getImmutable();
        H.h = getHashValue(R, SP, I, m);
    }

    public boolean Check(HashValue H, Randomness R, PublicParam SP, Element I, Element m) {
        return H.h.isEqual(getHashValue(R, SP, I, m));
    }

    public void Adapt(Randomness R_p, Randomness R, PublicParam SP, SecretKey sk, Element I, Element m, Element m_p) {
        Element gI = SP.g.mul(I).getImmutable();
        Element delta_m = m.sub(m_p).getImmutable();
        R_p.y_a = R.y_a.mul(gI.powZn(delta_m));
        R_p.g_a = R.g_a.mul(gI.powZn(delta_m.div(sk.x)));
    }
}
