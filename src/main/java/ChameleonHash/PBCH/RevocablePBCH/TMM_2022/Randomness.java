package ChameleonHash.PBCH.RevocablePBCH.TMM_2022;

import EllipticCurve.Point.Scalar;
import utils.ElementCounter;

public class Randomness extends ChameleonHash.PBCH.RevocablePBCH.Components.Randomness {
    Scalar r;

    @Override
    public final ElementCounter TheoSize() {
        ElementCounter res = new ElementCounter();
        res.count(this);
        return res;
    }
}
