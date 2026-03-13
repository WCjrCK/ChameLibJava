package scheme.IBCH.ZSS_2003;

import EllipticCurve.Point.MultivePoint;
import utils.ElementCounter;

public class HashValue extends scheme.IBCH.Components.HashValue<HashValue> {
    protected MultivePoint h;

    @Override
    public final boolean isEqual(HashValue other) {
        return h.isEqual(other.h);
    }

    @Override
    public final ElementCounter TheoSize() {
        ElementCounter res = new ElementCounter();
        res.count(this);
        return res;
    }
}
