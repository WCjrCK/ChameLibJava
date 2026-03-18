package ChameleonHash.IBCH.BaseIBCH.ZSS_2003;

import utils.ElementCounter;

public class Message extends ChameleonHash.IBCH.BaseIBCH.Components.Message {
    protected String m;

    public Message() {}

    public Message(String m) {
        this.m = m;
    }

    @Override
    public final ElementCounter TheoSize() {
        ElementCounter res = new ElementCounter();
        res.count(this);
        return res;
    }
}
