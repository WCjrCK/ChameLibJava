package Encryption.ABE.RevocableABE.TMM_2022;

import utils.ElementCounter;

public class Policy extends Encryption.ABE.Components.Policy {
    protected Encryption.ABE.BaseABE.FAME.Policy FAME_p;

    @Override
    public final ElementCounter TheoSize() {
        ElementCounter res = new ElementCounter();
        res.count(this);
        return res;
    }
}
