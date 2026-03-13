package scheme.IBCH.CZS_2014;

import utils.ElementCounter;

public class Identity extends scheme.IBCH.Components.Identity {
    protected String L;

    public Identity() {}

    public Identity(String ID) {
        this.L = ID;
    }

    @Override
    public final ElementCounter TheoSize() {
        ElementCounter res = new ElementCounter();
        res.count(this);
        return res;
    }
}
