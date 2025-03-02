package Signature.BLS;

import it.unisa.dia.gas.jpbc.Element;
import utils.Hash;

public class PBC {
    public static class PublicParam {
        public base.GroupParam.PBC.Asymmetry GP;
        Element g;

        public  PublicParam(curve.PBC curve, boolean swap_G1G2) {
            GP = new base.GroupParam.PBC.Asymmetry(curve, swap_G1G2);
            g = GP.GetG2Element();
        }

        public  PublicParam(base.GroupParam.PBC.Asymmetry GP) {
            this.GP = GP;
            g = GP.GetG2Element();
        }

        public Element H(String m) {
            return Hash.H_String_1_PBC_1(GP.G1, m);
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

    public void KeyGen(PublicKey PK, SecretKey SK, PublicParam SP) {
        SK.alpha = SP.GP.GetZrElement();
        PK.h = SP.g.powZn(SK.alpha).getImmutable();
    }

    public void Sign(Signature SIGN, SecretKey SK, PublicParam SP, String m) {
        SIGN.sigma_m = SP.H(m).powZn(SK.alpha).getImmutable();
    }

    public boolean Verify(PublicParam SP, PublicKey PK, Signature SIGN, String m) {
        return SP.GP.pairing(SIGN.sigma_m, SP.g).isEqual(SP.GP.pairing(SP.H(m), PK.h));
    }
}
