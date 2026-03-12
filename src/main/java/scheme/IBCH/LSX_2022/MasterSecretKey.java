package scheme.IBCH.LSX_2022;

import EllipticCurve.Point.AdditivePoint;
import EllipticCurve.Point.Point;
import utils.ElementCounter;

public class MasterSecretKey extends scheme.Components.MasterSecretKey {
    protected AdditivePoint alpha, beta;

    @Override
    public final String TheoSize() {
        ElementCounter res = new ElementCounter();
        res.count((Point) alpha);
        res.count((Point) beta);
        return res.toString();
    }
}
