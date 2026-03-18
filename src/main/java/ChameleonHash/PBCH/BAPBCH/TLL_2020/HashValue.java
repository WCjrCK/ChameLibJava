package ChameleonHash.PBCH.BAPBCH.TLL_2020;

import EllipticCurve.Point.MultivePoint;
import EllipticCurve.Point.Scalar;
import utils.ElementCounter;

public class HashValue extends ChameleonHash.PBCH.BasePBCH.Components.HashValue<HashValue> {
    MultivePoint b, h_p;
    Scalar[] owner_ID;

    @Override
    public boolean isEqual(HashValue other) {
        if (owner_ID.length != other.owner_ID.length) return false;
        for (int i = 0;i < owner_ID.length;++i) if (!owner_ID[i].isEqual(other.owner_ID[i])) return false;
        return b.isEqual(other.b) && h_p.isEqual(other.h_p);
    }

    @Override
    public final ElementCounter TheoSize() {
        ElementCounter res = new ElementCounter();
        res.count(this);
        return res;
    }
}
