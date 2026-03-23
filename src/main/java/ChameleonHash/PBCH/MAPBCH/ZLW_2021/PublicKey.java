package ChameleonHash.PBCH.MAPBCH.ZLW_2021;

import utils.ElementCounter;

public class PublicKey extends ChameleonHash.PBCH.MAPBCH.Components.PublicKey {
    protected Encryption.ABE.MAABE.Components.PublicKey MAABE_pk;

    @Override
    public ElementCounter TheoSize() {
        ElementCounter res = new ElementCounter();
        res.count(this);
        return res;
    }
}
