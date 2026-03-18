package ChameleonHash.CH.BaseCH.CCT_2024;

import EllipticCurve.Point.Scalar;
import utils.ElementCounter;

public class Randomness extends ChameleonHash.CH.BaseCH.Components.Randomness {
    protected Scalar z_1, z_2, c_1;

    @Override
    public final ElementCounter TheoSize() {
        ElementCounter res = new ElementCounter();
        res.count(this);
        return res;
    }
}

