package scheme.IBCH.LSX_2022;

import EllipticCurve.Point.AdditivePoint;
import utils.ElementCounter;

public class MasterSecretKey extends scheme.IBCH.Components.MasterSecretKey {
    protected AdditivePoint alpha, beta;

    @Override
    public final ElementCounter TheoSize() {
        ElementCounter res = new ElementCounter();
        res.count(this);
        return res;
    }
}
