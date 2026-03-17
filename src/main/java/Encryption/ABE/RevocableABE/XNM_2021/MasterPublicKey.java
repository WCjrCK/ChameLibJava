package Encryption.ABE.RevocableABE.XNM_2021;

import utils.ElementCounter;

public class MasterPublicKey extends Encryption.ABE.Components.MasterPublicKey {
    protected Encryption.ABE.BaseABE.FAME.MasterPublicKey FAME_mpk;

    @Override
    public final ElementCounter TheoSize() {
        ElementCounter res = new ElementCounter();
        res.count(this);
        return res;
    }
}
