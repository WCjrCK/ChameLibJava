package base.GroupParam.PBC;

import curve.Group;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Field;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import utils.Func;

import java.math.BigInteger;

@SuppressWarnings("rawtypes")
public class SingleGroup {
    public Field Zr, G;
    public BigInteger ndonr;

    public Element GetGElement() {
        return G.newRandomElement().getImmutable();
    }

    public Element GetZrElement() {
        return Zr.newRandomElement().getImmutable();
    }

    public SingleGroup(curve.PBC curve, Group group) {
        PairingParameters param = Func.PairingParam(curve);
        ndonr = Func.GetNdonr(group, param);
        Pairing pairing = PairingFactory.getPairing(param);
        this.G = Func.GetPBCField(pairing, group);
        this.Zr = pairing.getZr();
    }
}
