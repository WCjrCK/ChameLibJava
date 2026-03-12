package Signature.BLS;

import utils.ElementCounter;

public class Message extends Signature.Components.Message {
    String m;

    Message(String msg) {
        m = msg;
    }

    @Override
    public final ElementCounter TheoSize() {
        ElementCounter res = new ElementCounter();
        res.count(this);
        return res;
    }
}
