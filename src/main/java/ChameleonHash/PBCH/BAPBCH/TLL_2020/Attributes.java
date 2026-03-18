package ChameleonHash.PBCH.BAPBCH.TLL_2020;

import utils.ElementCounter;

public class Attributes extends ChameleonHash.PBCH.Components.Attributes {
    protected Encryption.ABE.Components.Attributes A;

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
