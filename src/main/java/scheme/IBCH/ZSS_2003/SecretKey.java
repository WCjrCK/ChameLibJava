package scheme.IBCH.ZSS_2003;

import EllipticCurve.Point.AdditivePoint;
import utils.ElementCounter;

public class SecretKey extends scheme.Components.SecretKey {
    protected AdditivePoint S_ID; // G_1

    @Override
    public final ElementCounter TheoSize() {
        ElementCounter res = new ElementCounter();
        res.count(this);
        return res;
    }
}
