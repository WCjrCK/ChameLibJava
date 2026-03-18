package ChameleonHash.CH.BaseCH.DSS_2020;

import EllipticCurve.Point.Scalar;
import utils.ElementCounter;

public class Randomness extends ChameleonHash.CH.BaseCH.Components.Randomness {
    protected Scalar e_1, e_2, s_1, s_2;

    @Override
    public final ElementCounter TheoSize() {
        ElementCounter res = new ElementCounter();
        res.count(this);
        return res;
    }
}

