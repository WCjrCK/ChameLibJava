package Encryption.ABE.RevocableABE.TMM_2022;

import utils.ElementCounter;

public class MasterPublicKey extends Encryption.ABE.RevocableABE.Components.MasterPublicKey {
    protected Encryption.ABE.BaseABE.FAME.MasterPublicKey FAME_mpk;

    @Override
    public final ElementCounter TheoSize() {
        ElementCounter res = new ElementCounter();
        res.count(this);
        return res;
    }
}
