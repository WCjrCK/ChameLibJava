package ChameleonHash.CH.CHET.KOG_CDK_2017;

import Commitment.NIZK_DL.Proof;
import EllipticCurve.Point.MultivePoint;
import utils.ElementCounter;

public class HashValue extends ChameleonHash.CH.CHET.Components.HashValue<HashValue> {
    protected MultivePoint b, h_p;
    protected Proof pi_t;

    @Override
    public final boolean isEqual(HashValue other) {
        return b.isEqual(other.b) && h_p.isEqual(other.h_p);
    }

    @Override
    public final ElementCounter TheoSize() {
        ElementCounter res = new ElementCounter();
        res.count(this);
        return res;
    }
}

