package Encryption.ABE.MAABE.RW_2015;

import MathStructure.LSSS;
import utils.ElementCounter;

public class Policy extends Encryption.ABE.MAABE.Components.Policy {
    public LSSS MSP = new LSSS();

    @Override
    public final ElementCounter TheoSize() {
        ElementCounter res = new ElementCounter();
        res.count(this);
        return res;
    }
}
