package scheme.IBCH.LSX_2022;

import EllipticCurve.Point.MultivePoint;
import EllipticCurve.Point.Point;
import utils.ElementCounter;

public class HashValue extends scheme.Components.HashValue {
    protected MultivePoint h;

    @Override
    public final boolean isEqual(scheme.Components.HashValue other) {
        if(!(other instanceof HashValue)) throw new IllegalArgumentException("哈希值不适配当前方案");
        return isEqual((HashValue) other);
    }


    public final boolean isEqual(HashValue other) {
        return h.isEqual(other.h);
    }

    @Override
    public final String TheoSize() {
        ElementCounter res = new ElementCounter();
        res.count((Point) h);
        return res.toString();
    }
}
