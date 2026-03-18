package ChameleonHash.IBCH.LabelIBCH.LJF_2025;

import EllipticCurve.Point.Scalar;
import utils.ElementCounter;

public class Message extends ChameleonHash.IBCH.LabelIBCH.Components.Message {
    protected Scalar m;

    public Message() {}

    @Override
    public final ElementCounter TheoSize() {
        ElementCounter res = new ElementCounter();
        res.count(this);
        return res;
    }
}
