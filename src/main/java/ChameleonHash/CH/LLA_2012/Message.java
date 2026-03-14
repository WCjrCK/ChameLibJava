package ChameleonHash.CH.LLA_2012;

import EllipticCurve.Point.MultivePoint;
import EllipticCurve.Point.Scalar;
import utils.ElementCounter;

public class Message extends ChameleonHash.CH.Components.Message {
    protected Scalar m;
    protected MultivePoint L, R;

    public Message() {}

    @Override
    public final ElementCounter TheoSize() {
        ElementCounter res = new ElementCounter();
        res.count(this);
        return res;
    }
}
