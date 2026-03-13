package scheme.IBCH.ZSS_2003;

import EllipticCurve.Point.AdditivePoint;
import utils.ElementCounter;

public class Randomness extends scheme.IBCH.Components.Randomness {
    protected AdditivePoint R;

    @Override
    public final ElementCounter TheoSize() {
        ElementCounter res = new ElementCounter();
        res.count(this);
        return res;
    }
}
