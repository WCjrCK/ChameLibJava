package scheme.IBCH.LJF_2025;

import EllipticCurve.Point.AdditivePoint;
import EllipticCurve.Point.MultivePoint;
import utils.ElementCounter;

public class Trapdoor extends scheme.Components.SecretKey {
    protected AdditivePoint td_1;
    protected MultivePoint td_2, td_3;

    @Override
    public final ElementCounter TheoSize() {
        ElementCounter res = new ElementCounter();
        res.count(this);
        return res;
    }
}
