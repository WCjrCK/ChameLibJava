package scheme.IBCH.XSL_2021;

import EllipticCurve.Point.MultivePoint;
import utils.ElementCounter;

public class HashValue extends scheme.Components.HashValue {
    protected MultivePoint h;

    @Override
    public final boolean isEqual(scheme.Components.HashValue other) {
        if(!(other instanceof HashValue)) throw new IllegalArgumentException("哈希值不适配当前方案");
        return h.isEqual(((HashValue) other).h);
    }

    @Override
    public final ElementCounter TheoSize() {
        ElementCounter res = new ElementCounter();
        res.count(this);
        return res;
    }
}
