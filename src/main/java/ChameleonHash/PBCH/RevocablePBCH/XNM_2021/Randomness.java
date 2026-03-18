package ChameleonHash.PBCH.RevocablePBCH.XNM_2021;

import utils.ElementCounter;

public class Randomness extends ChameleonHash.PBCH.RevocablePBCH.Components.Randomness {
    protected ChameleonHash.CH.CHET.Components.Randomness CHET_r;

    @Override
    public final ElementCounter TheoSize() {
        ElementCounter res = new ElementCounter();
        res.count(this);
        return res;
    }
}
