package ChameleonHash.PBCH.MAPBCH.MXN_2022;

import utils.ElementCounter;

public class SecretKeyGroup extends ChameleonHash.PBCH.MAPBCH.Components.SecretKeyGroup {
    protected Encryption.ABE.MAABE.RW_2015.SecretKeyGroup MAABE_SKG;

    public SecretKeyGroup(Encryption.ABE.MAABE.RW_2015.SecretKeyGroup skg) {
        MAABE_SKG = skg;
    }

    @Override
    public ElementCounter TheoSize() {
        ElementCounter res = new ElementCounter();
        res.count(this);
        return res;
    }
}
