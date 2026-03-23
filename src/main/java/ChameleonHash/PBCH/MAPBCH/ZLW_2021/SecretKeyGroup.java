package ChameleonHash.PBCH.MAPBCH.ZLW_2021;

import utils.ElementCounter;

public class SecretKeyGroup extends ChameleonHash.PBCH.MAPBCH.Components.SecretKeyGroup {
    protected Encryption.ABE.MAABE.Components.SecretKeyGroup MAABE_SKG;

    public SecretKeyGroup(Encryption.ABE.MAABE.Components.SecretKeyGroup skg) {
        MAABE_SKG = skg;
    }

    @Override
    public ElementCounter TheoSize() {
        ElementCounter res = new ElementCounter();
        res.count(this);
        return res;
    }
}
