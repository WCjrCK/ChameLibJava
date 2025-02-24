package base.GroupParam.PBC;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Field;
import it.unisa.dia.gas.jpbc.Pairing;
import utils.Func;

@SuppressWarnings({"rawtypes", "unused"})
public class Symmetry {
    Pairing pairing;
    public Field Zr, G, GT;

    public Element pairing(Element g1, Element g2) {
        return pairing.pairing(g1, g2).getImmutable();
    }

    public Element GetGElement() {
        return G.newRandomElement().getImmutable();
    }

    public Element GetGTElement() {
        return GT.newRandomElement().getImmutable();
    }

    public Element GetZrElement() {
        return Zr.newRandomElement().getImmutable();
    }

    public Symmetry(curve.PBC curve) {
        this.pairing = Func.PairingGen(curve);
        this.G = this.pairing.getG1();
        this.GT = this.pairing.getGT();
        this.Zr = this.pairing.getZr();
    }
}
