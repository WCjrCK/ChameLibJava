package ChameleonHash.IBCH.BaseIBCH.ZSS_2003;

import EllipticCurve.Point.AdditivePoint;
import utils.ElementCounter;

public class Randomness extends ChameleonHash.IBCH.BaseIBCH.Components.Randomness {
    protected AdditivePoint R;

    @Override
    public final ElementCounter TheoSize() {
        ElementCounter res = new ElementCounter();
        res.count(this);
        return res;
    }
}
