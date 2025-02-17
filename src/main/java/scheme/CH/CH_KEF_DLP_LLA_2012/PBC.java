package scheme.CH.CH_KEF_DLP_LLA_2012;

import curve.Group;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Field;
import utils.Func;
import utils.Hash;

import java.math.BigInteger;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;

@SuppressWarnings("rawtypes")
public class PBC {
    public static class Label {
        public Element L, R;
    }

    public static class LabelGen {
        public Element y_1, omega_1;
    }

    public static class LabelManager {
        Map<PublicKey, LabelGen> Dict = new HashMap<>();
        Field G;

        public void add(PublicKey pk, LabelGen lg) {
            Dict.put(pk, lg);
        }

        public void get(Label L, PublicKey pk) {
            Element t = G.newRandomElement().getImmutable();
            BigInteger H2_t = H2(t);
            LabelGen lg = Dict.get(pk);
            L.L = lg.y_1.pow(H2_t).getImmutable();
            L.R = t.mul(lg.omega_1.pow(H2_t)).getImmutable();
        }
    }

    public static class PublicKey {
        public Element g, y_2;
    }

    public static class SecretKey {
        public BigInteger alpha, x_1, x_2;
    }

    public static class HashValue {
        public Element S;
    }

    public static class Randomness {
        BigInteger r;
    }

    Random rand = new Random();
    Field G;

    private static BigInteger H1(Element m1, Element m2, Element m3) {
        return Hash.H_PBC_3_native_1(m1, m2, m3);
    }

    private static BigInteger H2(Element m1) {
        return Hash.H_PBC_1_native_1(m1);
    }

    private Element getHashValue(Randomness r, Label L, PublicKey pk, BigInteger m) {
        return pk.g.pow(m).mul(L.L.mul(pk.y_2.pow(H1(L.L, L.R, L.L))).pow(r.r));
    }

    public PBC(LabelManager lm, curve.PBC curve, Group group) {
        G = Func.GetPBCField(Func.PairingGen(curve), group);
        lm.G = G;
    }

    public void KeyGen(LabelManager lm, PublicKey pk, SecretKey sk) {
        pk.g = G.newRandomElement().getImmutable();
        sk.alpha = Func.getZq(rand, G.getOrder());
        sk.x_1 = Func.getZq(rand, G.getOrder());
        sk.x_2 = Func.getZq(rand, G.getOrder());
        LabelGen lg = new LabelGen();
        lg.y_1 = pk.g.pow(sk.x_1).getImmutable();
        lg.omega_1 = lg.y_1.pow(sk.alpha).getImmutable();
        pk.y_2 = pk.g.pow(sk.x_2).getImmutable();
        lm.add(pk, lg);
    }

    public void Hash(HashValue h, Randomness r, Label L, LabelManager lm, PublicKey pk, BigInteger m) {
        lm.get(L, pk);
        r.r = Func.getZq(rand, G.getOrder());
        h.S = getHashValue(r, L, pk, m).getImmutable();
    }

    public boolean Check(HashValue h, Randomness r, PublicKey pk, Label L, BigInteger m) {
        return h.S.isEqual(getHashValue(r, L, pk, m));
    }

    public void UForge(Randomness r_p, HashValue h, Randomness r, Label L, PublicKey pk, SecretKey sk, BigInteger m, BigInteger m_p) {
        if(!Check(h, r, pk, L, m)) throw new RuntimeException("illegal hash");
        Element t = L.R.div(L.L.pow(sk.alpha));
        BigInteger H2_t = H2(t), c = H1(L.L, L.R, L.L);
        if(!pk.g.pow(H2_t.multiply(sk.x_1)).isEqual(L.L)) throw new RuntimeException("illegal label");
        r_p.r = r.r.add(m.subtract(m_p).multiply(sk.x_1.multiply(H2_t).add(sk.x_2.multiply(c)).modInverse(G.getOrder()))).mod(G.getOrder());
    }

    public void IForge(Randomness r_pp, Randomness r, Randomness r_p, BigInteger m, BigInteger m_p, BigInteger m_pp) {
        r_pp.r = r_p.r.add(m.subtract(m_p).modInverse(G.getOrder()).multiply(r_p.r.subtract(r.r)).multiply(m_p.subtract(m_pp))).mod(G.getOrder());
    }
}
