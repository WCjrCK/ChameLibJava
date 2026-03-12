package scheme.IBCH.implement.ZSS_2003;

import utils.ElementCounter;

public class Message extends scheme.Components.Message {
    protected String m;

    public Message() {}

    public Message(String m) {
        this.m = m;
    }

    @Override
    public final String TheoSize() {
        ElementCounter res = new ElementCounter();
        return res.toString();
    }
}
