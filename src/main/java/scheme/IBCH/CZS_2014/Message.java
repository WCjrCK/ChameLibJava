package scheme.IBCH.CZS_2014;

import EllipticCurve.Point.AdditivePoint;
import utils.ElementCounter;

public class Message extends scheme.IBCH.Components.Message {
    protected AdditivePoint m;

    public Message() {}

    @Override
    public final ElementCounter TheoSize() {
        ElementCounter res = new ElementCounter();
        res.count(this);
        return res;
    }
}
