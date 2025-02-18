package scheme.IBCH;

import java.util.Random;

import curve.Group;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Field;
import it.unisa.dia.gas.jpbc.Pairing;
import utils.Func;

@SuppressWarnings("rawtypes")
public class PbcScheme {
    public Random rand = new Random();
    public Field G1,G2,GT,Zn;
    public Pairing pairing;

    // scheme with pairing, symmetric group
    public PbcScheme(curve.PBC curve) {
        pairing = Func.PairingGen(curve);

        G1 = Func.GetPBCField(pairing, Group.G1);
        G2 = Func.GetPBCField(pairing, Group.G2);
        GT = Func.GetPBCField(pairing, Group.GT);
        Zn = pairing.getZr();
    }

    // scheme with pairing, ssymmetric group
    public PbcScheme(curve.PBC curve, Group group_G1, Group group_G2) {
        pairing = Func.PairingGen(curve);

        G1 = Func.GetPBCField(pairing, group_G1);
        G2 = Func.GetPBCField(pairing, group_G2);
        GT = Func.GetPBCField(pairing, Group.GT);
        Zn = pairing.getZr();
    }

    // scheme without pairing
    public PbcScheme(curve.PBC curve, Group group) {
        pairing = Func.PairingGen(curve);

        G1 = Func.GetPBCField(pairing, group);
        Zn = pairing.getZr();
    }

    public Element GetZnElement() {
        return Zn.newRandomElement().getImmutable();
    }

    public Element GetG1Element(){
        return G1.newRandomElement().getImmutable();
    }

    public Element GetG2Element(){
        return G2.newRandomElement().getImmutable();
    }

    public Element GetGTElement(){
        return GT.newRandomElement().getImmutable();
    }
}
