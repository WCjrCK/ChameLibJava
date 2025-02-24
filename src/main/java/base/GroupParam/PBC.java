package base.GroupParam;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Field;
import it.unisa.dia.gas.jpbc.Pairing;
import utils.Func;

@SuppressWarnings("rawtypes")
public class PBC {
    Pairing pairing;
    boolean swap_G1G2;
    public Field Zr, G1, G2, GT;

    public Element pairing(Element g1, Element g2) {
        if(swap_G1G2) return pairing.pairing(g2, g1).getImmutable();
        else return pairing.pairing(g1, g2).getImmutable();
    }

    public Element GetG1Element() {
        return G1.newRandomElement().getImmutable();
    }

    public Element GetG2Element() {
        return G2.newRandomElement().getImmutable();
    }

    public Element GetGTElement() {
        return GT.newRandomElement().getImmutable();
    }

    public Element GetZrElement() {
        return Zr.newRandomElement().getImmutable();
    }

    public PBC(curve.PBC curve, boolean swap_G1G2) {
        this.swap_G1G2 = swap_G1G2;
        this.pairing = Func.PairingGen(curve);
        if(swap_G1G2) {
            this.G1 = this.pairing.getG2();
            this.G2 = this.pairing.getG1();
        } else {
            this.G1 = this.pairing.getG1();
            this.G2 = this.pairing.getG2();
        }
        this.GT = this.pairing.getGT();
        this.Zr = this.pairing.getZr();
    }
}
