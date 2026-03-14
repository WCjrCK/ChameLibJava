package scheme.IBCH.LSX_2022;

import EllipticCurve.Point.MultivePoint;
import EllipticCurve.Point.Scalar;
import utils.ElementCounter;

public class Randomness extends scheme.IBCH.Components.Randomness {
    protected Scalar r_1;
    protected MultivePoint r_2;

    @Override
    public final ElementCounter TheoSize() {
        ElementCounter res = new ElementCounter();
        res.count(this);
        return res;
    }
}
