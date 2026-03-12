package scheme.IBCH.LJF_2025;

import EllipticCurve.Point.AdditivePoint;
import EllipticCurve.Point.MultivePoint;
import utils.ElementCounter;

public class Randomness extends scheme.Components.Randomness {
    protected AdditivePoint r_1;
    protected MultivePoint r_2, r_3;

    @Override
    public final ElementCounter TheoSize() {
        ElementCounter res = new ElementCounter();
        res.count(this);
        return res;
    }
}
