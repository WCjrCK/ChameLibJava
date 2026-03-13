package scheme.IBCH.CZS_2014;

import EllipticCurve.Point.AdditivePoint;
import EllipticCurve.Point.MultivePoint;
import utils.ElementCounter;

public class Randomness extends scheme.IBCH.Components.Randomness {
    protected AdditivePoint r_1;
    protected MultivePoint r_2; // G_1

    @Override
    public final ElementCounter TheoSize() {
        ElementCounter res = new ElementCounter();
        res.count(this);
        return res;
    }
}
