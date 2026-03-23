package ChameleonHash.PBCH.MAPBCH.MXN_2022;

import utils.ElementCounter;

public class SecretKey extends ChameleonHash.PBCH.MAPBCH.Components.SecretKey {
    protected Encryption.ABE.MAABE.Components.SecretKey MAABE_sk;

    @Override
    public ElementCounter TheoSize() {
        ElementCounter res = new ElementCounter();
        res.count(this);
        return res;
    }
}
