package ChameleonHash.PBCH.MAPBCH.MXN_2022;

import utils.ElementCounter;

public class Policy extends ChameleonHash.PBCH.MAPBCH.Components.Policy {
    protected Encryption.ABE.MAABE.RW_2015.Policy MAABE_P;

    @Override
    public ElementCounter TheoSize() {
        ElementCounter res = new ElementCounter();
        res.count(this);
        return res;
    }
}
