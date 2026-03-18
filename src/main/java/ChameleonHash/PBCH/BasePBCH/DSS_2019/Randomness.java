package ChameleonHash.PBCH.BasePBCH.DSS_2019;

import utils.ElementCounter;

public class Randomness extends ChameleonHash.PBCH.BasePBCH.Components.Randomness {
    protected ChameleonHash.CH.CHET.Components.Randomness CHET_r;

    @Override
    public final ElementCounter TheoSize() {
        ElementCounter res = new ElementCounter();
        res.count(this);
        return res;
    }
}
