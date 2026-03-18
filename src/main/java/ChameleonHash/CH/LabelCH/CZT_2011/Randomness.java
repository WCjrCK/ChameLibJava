package ChameleonHash.CH.LabelCH.CZT_2011;

import EllipticCurve.Point.MultivePoint;
import utils.ElementCounter;

public class Randomness extends ChameleonHash.CH.LabelCH.Components.Randomness {
    protected MultivePoint g_a, y_a;

    @Override
    public final ElementCounter TheoSize() {
        ElementCounter res = new ElementCounter();
        res.count(this);
        return res;
    }
}

