package Signature.BLS;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Field;
import it.unisa.dia.gas.jpbc.Pairing;
import utils.Func;
import utils.Hash;

@SuppressWarnings("rawtypes")
public class PBC {
    public static class PublicParam {
        Pairing pairing;
        Field Zr, G1, G2, GT;
        boolean swap_G1G2;
        Element g;

        public Element pairing(Element g1, Element g2) {
            if(swap_G1G2) return pairing.pairing(g2, g1).getImmutable();
            else return pairing.pairing(g1, g2).getImmutable();
        }

        public Element H(String m) {
            return Hash.H_String_1_PBC_1(G1, m);
        }

        public Element GetG2Element() {
            return G2.newRandomElement().getImmutable();
        }

        public Element GetZrElement() {
            return Zr.newRandomElement().getImmutable();
        }
    }

    public static class SecretKey {
        public Element alpha;
    }

    public static class PublicKey {
        public Element h;
    }

    public static class Signature {
        public Element sigma_m;

        public boolean isEqual(Signature sign) {
            return sigma_m.equals(sign.sigma_m);
        }
    }

    public void SetUp(PublicParam SP, curve.PBC curve, boolean swap_G1G2) {
        SP.swap_G1G2 = swap_G1G2;
        SP.pairing = Func.PairingGen(curve);
        if(swap_G1G2) {
            SP.G1 = SP.pairing.getG2();
            SP.G2 = SP.pairing.getG1();
        } else {
            SP.G1 = SP.pairing.getG1();
            SP.G2 = SP.pairing.getG2();
        }
        SP.GT = SP.pairing.getGT();
        SP.Zr = SP.pairing.getZr();
        SP.g = SP.GetG2Element();
    }

    public void KeyGen(PublicKey PK, SecretKey SK, PublicParam SP) {
        SK.alpha = SP.GetZrElement();
        PK.h = SP.g.powZn(SK.alpha).getImmutable();
    }

    public void Sign(Signature SIGN, SecretKey SK, PublicParam SP, String m) {
        SIGN.sigma_m = SP.H(m).powZn(SK.alpha).getImmutable();
    }

    public boolean Verify(PublicParam SP, PublicKey PK, Signature SIGN, String m) {
        return SP.pairing(SIGN.sigma_m, SP.g).isEqual(SP.pairing(SP.H(m), PK.h));
    }
}
