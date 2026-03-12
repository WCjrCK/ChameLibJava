package scheme.IBCH.implement.LSX_2022;

import EllipticCurve.Point.AdditivePoint;
import utils.ElementCounter;

public class Identity extends scheme.Components.Identity {
    protected AdditivePoint ID;

    public Identity() {}

    @Override
    public final String TheoSize() {
        ElementCounter res = new ElementCounter();
        return res.toString();
    }
}
