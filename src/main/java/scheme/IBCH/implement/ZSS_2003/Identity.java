package scheme.IBCH.implement.ZSS_2003;

import utils.ElementCounter;

public class Identity extends scheme.Components.Identity {
    protected String ID;

    public Identity() {}

    public Identity(String ID) {
        this.ID = ID;
    }

    @Override
    public final String TheoSize() {
        ElementCounter res = new ElementCounter();
        return res.toString();
    }
}
