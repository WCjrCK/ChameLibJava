package scheme.IBCH.ZSS_2003;

import utils.ElementCounter;

public class Identity extends scheme.IBCH.Components.Identity {
    protected String ID;

    public Identity() {}

    public Identity(String ID) {
        this.ID = ID;
    }

    @Override
    public final ElementCounter TheoSize() {
        ElementCounter res = new ElementCounter();
        res.count(this);
        return res;
    }
}
