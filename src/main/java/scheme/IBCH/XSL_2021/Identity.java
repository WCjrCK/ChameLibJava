package scheme.IBCH.XSL_2021;

import utils.ElementCounter;

import java.util.BitSet;

public class Identity extends scheme.Components.Identity {
    protected BitSet I;

    public Identity() {}

    @Override
    public final String TheoSize() {
        ElementCounter res = new ElementCounter();
        return res.toString();
    }
}
