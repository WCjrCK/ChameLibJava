package ChameleonHash.CH.BaseCH.DKS_2020;

import EllipticCurve.Point.Scalar;
import utils.ElementCounter;

public class Randomness extends ChameleonHash.CH.BaseCH.Components.Randomness {
    protected Scalar e_1, e_2, s_1_1, s_1_2, s_2;

    @Override
    public final ElementCounter TheoSize() {
        ElementCounter res = new ElementCounter();
        res.count(this);
        return res;
    }
}

