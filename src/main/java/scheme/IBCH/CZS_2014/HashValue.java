package scheme.IBCH.CZS_2014;

import EllipticCurve.Point.AdditivePoint;
import utils.ElementCounter;

public class HashValue extends scheme.Components.HashValue {
    protected AdditivePoint h;

    @Override
    public final boolean isEqual(scheme.Components.HashValue other) {
        if(!(other instanceof HashValue)) throw new IllegalArgumentException("哈希值不适配当前方案");
        return isEqual((HashValue) other);
    }


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
