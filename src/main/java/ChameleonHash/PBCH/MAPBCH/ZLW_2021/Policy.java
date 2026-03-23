package ChameleonHash.PBCH.MAPBCH.ZLW_2021;

import utils.ElementCounter;

public class Policy extends ChameleonHash.PBCH.MAPBCH.Components.Policy {
    protected Encryption.ABE.MAABE.Components.Policy MAABE_P;

    @Override
    public ElementCounter TheoSize() {
        ElementCounter res = new ElementCounter();
        res.count(this);
        return res;
    }
}
