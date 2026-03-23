package ChameleonHash.PBCH.MAPBCH.MXN_2022;

import utils.ElementCounter;

public class Randomness extends ChameleonHash.PBCH.MAPBCH.Components.Randomness {
    protected ChameleonHash.CH.CHET.Components.Randomness CHET_r;

    @Override
    public ElementCounter TheoSize() {
        ElementCounter res = new ElementCounter();
        res.count(this);
        return res;
    }
}
