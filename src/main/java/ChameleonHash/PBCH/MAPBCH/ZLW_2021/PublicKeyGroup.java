package ChameleonHash.PBCH.MAPBCH.ZLW_2021;

import utils.ElementCounter;

public class PublicKeyGroup extends ChameleonHash.PBCH.MAPBCH.Components.PublicKeyGroup {
    protected Encryption.ABE.MAABE.Components.PublicKeyGroup MAABE_PKG;

    public PublicKeyGroup(Encryption.ABE.MAABE.Components.PublicKeyGroup pkg) {
        MAABE_PKG = pkg;
    }

    @Override
    public ElementCounter TheoSize() {
        ElementCounter res = new ElementCounter();
        res.count(this);
        return res;
    }
}
