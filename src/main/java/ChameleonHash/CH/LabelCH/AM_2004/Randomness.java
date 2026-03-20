package ChameleonHash.CH.LabelCH.AM_2004;

import EllipticCurve.Point.MultivePoint;
import utils.ElementCounter;

public class Randomness extends ChameleonHash.CH.LabelCH.Components.Randomness {
    protected MultivePoint g_r;

    @Override
    public final ElementCounter TheoSize() {
        ElementCounter res = new ElementCounter();
        res.count(this);
        return res;
    }
}
