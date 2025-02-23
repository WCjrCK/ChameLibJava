package AE.PKE_CCA_AMV_2017;

import curve.Group;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Field;
import it.unisa.dia.gas.jpbc.Pairing;
import utils.Func;
import utils.Hash;

import java.util.HashMap;

/*
 * Redactable Blockchain or Rewriting History in Bitcoin and Friends
 * P25. 4.4.2 Random Oracle Model Instantiation
 */

@SuppressWarnings("rawtypes")
public class PBC {
    public static class PublicParam {
        Field Zr, G;
        public Element g_1, g_2;
        // due to wrong behave in many curve & group at elementfrombyte, have to make map to implement Omega
        public HashMap<String, Element> Omega = new HashMap<>();
        public HashMap<String, Element> Omega_inv = new HashMap<>();

        private Element H(String m) {
            return Hash.H_String_1_PBC_1(Zr, m);
        }

        public Element H(Element m1, Element m2, Element m3) {
            return H(String.format("%s|%s|%s", m1, m2, m3));
        }

        public Element GetGElement() {
            return G.newRandomElement().getImmutable();
        }

        public Element GetZrElement() {
            return Zr.newRandomElement().getImmutable();
        }

        public Element Omega(Element m) {
            if(Omega.containsKey(m.toString())) return Omega.get(m.toString());
            Element res = G.newRandomElement().getImmutable();
            Omega.put(m.toString(), res);
            Omega_inv.put(res.toString(), m);
            return res;
        }

        public Element Omega_inv(Element m) {
            return Omega_inv.get(m.toString());
        }
    }

    public static class PublicKey {
        public Element y_1, y_2, y_3;
    }

    public static class SecretKey {
        public Element x_1_1, x_2_1, x_1_2, x_2_2, x_1_3, x_2_3;
    }

    public static class CipherText {
        public Element c_1, c_2, c_3, c_4;
    }

    public static class PlainText {
        public Element m;

        public boolean isEqual(PlainText pt) {
            return m.isEqual(pt.m);
        }
    }

    public void SetUp(PublicParam pp, curve.PBC curve, Group group) {
        Pairing pairing = Func.PairingGen(curve);
        pp.G = Func.GetPBCField(pairing, group);
        pp.Zr = pairing.getZr();
        pp.g_1 = pp.GetGElement();
        pp.g_2 = pp.GetGElement();
    }

    public void KeyGen(PublicKey pk, SecretKey sk, PublicParam pp) {
        sk.x_1_1 = pp.GetZrElement();
        sk.x_2_1 = pp.GetZrElement();
        sk.x_1_2 = pp.GetZrElement();
        sk.x_2_2 = pp.GetZrElement();
        sk.x_1_3 = pp.GetZrElement();
        sk.x_2_3 = pp.GetZrElement();

        pk.y_1 = pp.g_1.powZn(sk.x_1_1).mul(pp.g_2.powZn(sk.x_2_1)).getImmutable();
        pk.y_2 = pp.g_1.powZn(sk.x_1_2).mul(pp.g_2.powZn(sk.x_2_2)).getImmutable();
        pk.y_3 = pp.g_1.powZn(sk.x_1_3).mul(pp.g_2.powZn(sk.x_2_3)).getImmutable();
    }

    public void Encrypt(CipherText CT, PublicParam pp, PublicKey pk, PlainText PT) {
        Element rho = pp.GetZrElement();
        Encrypt(CT, pp, pk, PT, rho);
    }

    public void Encrypt(CipherText CT, PublicParam pp, PublicKey pk, PlainText PT, Element rho) {
        CT.c_1 = pp.g_1.powZn(rho).getImmutable();
        CT.c_2 = pp.g_2.powZn(rho).getImmutable();
        CT.c_3 = pk.y_3.powZn(rho).mul(pp.Omega(PT.m)).getImmutable();
        CT.c_4 = pk.y_1.powZn(rho).mul(pk.y_2.powZn(rho.mul(pp.H(CT.c_1, CT.c_2, CT.c_3)))).getImmutable();
    }

    public void Decrypt(PlainText PT, PublicParam pp, SecretKey sk, CipherText CT) {
        if(!CT.c_4.isEqual(
                CT.c_1.powZn(sk.x_1_1).mul(CT.c_2.powZn(sk.x_2_1)).mul(
                    CT.c_1.powZn(sk.x_1_2).mul(CT.c_2.powZn(sk.x_2_2)).powZn(pp.H(CT.c_1, CT.c_2, CT.c_3))
                )
        )) throw new RuntimeException("wrong cipher text");
        PT.m = pp.Omega_inv(CT.c_3.div(CT.c_1.powZn(sk.x_1_3).mul(CT.c_2.powZn(sk.x_2_3))));
    }
}
