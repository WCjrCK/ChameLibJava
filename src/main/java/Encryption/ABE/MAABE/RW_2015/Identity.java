package Encryption.ABE.MAABE.RW_2015;

import utils.ElementCounter;

public class Identity extends Encryption.ABE.MAABE.Components.Identity {
    String id;

    public Identity(String id) {
        this.id = id;
    }

    @Override
    public final ElementCounter TheoSize() {
        ElementCounter res = new ElementCounter();
        res.count(this);
        return res;
    }
}
