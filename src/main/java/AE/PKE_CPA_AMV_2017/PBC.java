package AE.PKE_CPA_AMV_2017;

/*
 * Redactable Blockchain or Rewriting History in Bitcoin and Friends
 * P25. 4.4.2 Random Oracle Model Instantiation
 */

import curve.Group;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Field;
import it.unisa.dia.gas.jpbc.Pairing;
import utils.Func;
import utils.Hash;

import java.util.HashMap;

@SuppressWarnings("rawtypes")
public class PBC {
    public static class PublicParam {
        Field Zr, G;
        Element g;
        // due to wrong behave in many curve & group at elementfrombyte, have to make map to implement Omega
        HashMap<String, Element> Omega = new HashMap<>();
        HashMap<String, Element> Omega_inv = new HashMap<>();

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
        public Element y;
    }

    public static class SecretKey {
        public Element x;
    }

    public static class CipherText {
        public Element c_1, c_2;
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
        pp.g = pp.GetGElement();
    }

    public void KeyGen(PublicKey pk, SecretKey sk, PublicParam pp) {
        sk.x = pp.GetZrElement();
        pk.y = pp.g.powZn(sk.x).getImmutable();
    }

    public void Encrypt(CipherText CT, PublicParam pp, PublicKey pk, PlainText PT) {
        Element rho = pp.GetZrElement();
        CT.c_1 = pp.g.powZn(rho).getImmutable();
        CT.c_2 = pk.y.powZn(rho).mul(pp.Omega(PT.m)).getImmutable();
    }

    public void Decrypt(PlainText PT, PublicParam pp, SecretKey sk, CipherText CT) {
        PT.m = pp.Omega_inv(CT.c_2.div(CT.c_1.powZn(sk.x)));
    }
}
