package scheme.IBCH.implement.LSX_2022;

import EllipticCurve.Point.AdditivePoint;
import EllipticCurve.Point.Point;
import utils.ElementCounter;

public class MasterSecretKey extends scheme.Components.MasterSecretKey {
    protected AdditivePoint alpha, beta; // Z_p

    @Override
    public final String TheoSize() {
        ElementCounter res = new ElementCounter();
        res.count((Point) alpha);
        res.count((Point) beta);
        return res.toString();
    }
}
