package scheme.IBCH.implement.ZSS_2003.S1;

import EllipticCurve.Point.MultivePoint;

public class HashValue extends scheme.Components.HashValue {
    MultivePoint h; // G_T

    @Override
    public final boolean isEqual(scheme.Components.HashValue other) {
        if(!(other instanceof HashValue)) throw new IllegalArgumentException("哈希值不适配当前方案");
        return isEqual((HashValue) other);
    }


    public final boolean isEqual(HashValue other) {
        return h.isEqual(other.h);
    }
}
