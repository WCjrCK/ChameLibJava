package base.GroupParam.PBC;

import curve.Group;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Field;
import it.unisa.dia.gas.jpbc.Pairing;
import utils.Func;

@SuppressWarnings("rawtypes")
public class SingleGroup {
    public Field Zr, G;

    public Element GetGElement() {
        return G.newRandomElement().getImmutable();
    }

    public Element GetZrElement() {
        return Zr.newRandomElement().getImmutable();
    }

    public SingleGroup(curve.PBC curve, Group group) {
        Pairing pairing = Func.PairingGen(curve);
        this.G = Func.GetPBCField(pairing, group);
        this.Zr = pairing.getZr();
    }
}
