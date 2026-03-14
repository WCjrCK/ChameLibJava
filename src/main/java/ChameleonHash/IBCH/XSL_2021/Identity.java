package ChameleonHash.IBCH.XSL_2021;

import utils.ElementCounter;

import java.util.BitSet;

public class Identity extends ChameleonHash.IBCH.Components.Identity {
    protected BitSet I;

    public Identity() {}

    @Override
    public final ElementCounter TheoSize() {
        ElementCounter res = new ElementCounter();
        res.count(this);
        return res;
    }
}
