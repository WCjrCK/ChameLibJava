package ChameleonHash.PBCH.BasePBCH.DSS_2019;

import utils.ElementCounter;

public class Attributes extends ChameleonHash.PBCH.BasePBCH.Components.Attributes {
    protected Encryption.ABE.BaseABE.Components.Attributes A;

    @Override
    public final void addAttr(String attr) {
        A.addAttr(attr);
    }

    @Override
    public final ElementCounter TheoSize() {
        ElementCounter res = new ElementCounter();
        res.count(this);
        return res;
    }
}
