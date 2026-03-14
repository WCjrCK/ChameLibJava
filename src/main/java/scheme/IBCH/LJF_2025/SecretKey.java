package scheme.IBCH.LJF_2025;

import EllipticCurve.Point.MultivePoint;
import EllipticCurve.Point.Scalar;
import utils.ElementCounter;

public class SecretKey extends scheme.IBCH.Components.SecretKey {
    protected Scalar td_1;
    protected MultivePoint td_2;

    @Override
    public final ElementCounter TheoSize() {
        ElementCounter res = new ElementCounter();
        res.count(this);
        return res;
    }
}
