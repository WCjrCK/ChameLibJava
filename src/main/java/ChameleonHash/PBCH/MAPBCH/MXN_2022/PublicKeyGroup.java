package ChameleonHash.PBCH.MAPBCH.MXN_2022;

import utils.ElementCounter;

public class PublicKeyGroup extends ChameleonHash.PBCH.MAPBCH.Components.PublicKeyGroup {
    protected Encryption.ABE.MAABE.RW_2015.PublicKeyGroup MAABE_PKG;

    public PublicKeyGroup(Encryption.ABE.MAABE.RW_2015.PublicKeyGroup pkg) {
        MAABE_PKG = pkg;
    }

    @Override
    public ElementCounter TheoSize() {
        ElementCounter res = new ElementCounter();
        res.count(this);
        return res;
    }
}
