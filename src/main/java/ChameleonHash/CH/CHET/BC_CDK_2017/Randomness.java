package ChameleonHash.CH.CHET.BC_CDK_2017;

import utils.ElementCounter;

public class Randomness extends ChameleonHash.CH.Components.Randomness {
    protected ChameleonHash.CH.Components.Randomness r_1, r_2;

    @Override
    public final ElementCounter TheoSize() {
        ElementCounter res = new ElementCounter();
        res.count(this);
        return res;
    }
}

