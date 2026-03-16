package ChameleonHash.PBCH.BasePBCH.DSS_2019;

import utils.ElementCounter;

public class SecretKey extends ChameleonHash.PBCH.Components.SecretKey {
    protected ChameleonHash.CH.Components.SecretKey CHET_sk;
    protected Encryption.ABE.FAME.SecretKey FAME_sk;

    @Override
    public final ElementCounter TheoSize() {
        ElementCounter res = new ElementCounter();
        res.count(this);
        return res;
    }
}
