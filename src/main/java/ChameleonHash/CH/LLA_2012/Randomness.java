package ChameleonHash.CH.LLA_2012;

import EllipticCurve.Point.Scalar;
import utils.ElementCounter;

public class Randomness extends ChameleonHash.CH.Components.Randomness {
    protected Scalar r;

    @Override
    public final ElementCounter TheoSize() {
        ElementCounter res = new ElementCounter();
        res.count(this);
        return res;
    }
}
