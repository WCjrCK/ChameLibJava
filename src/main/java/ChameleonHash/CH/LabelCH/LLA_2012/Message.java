package ChameleonHash.CH.LabelCH.LLA_2012;

import EllipticCurve.Point.Scalar;
import utils.ElementCounter;

public class Message extends ChameleonHash.CH.Components.Message {
    protected Scalar m;

    public Message() {}

    @Override
    public final ElementCounter TheoSize() {
        ElementCounter res = new ElementCounter();
        res.count(this);
        return res;
    }
}
