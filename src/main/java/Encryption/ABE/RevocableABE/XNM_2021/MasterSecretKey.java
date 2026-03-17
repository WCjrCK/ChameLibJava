package Encryption.ABE.RevocableABE.XNM_2021;

import utils.ElementCounter;

public class MasterSecretKey extends Encryption.ABE.Components.MasterSecretKey {
    protected Encryption.ABE.BaseABE.FAME.MasterSecretKey FAME_msk;

    @Override
    public final ElementCounter TheoSize() {
        ElementCounter res = new ElementCounter();
        res.count(this);
        return res;
    }
}
