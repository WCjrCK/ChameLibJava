package scheme.IBCH.XSL_2021;

import EllipticCurve.Point.AdditivePoint;
import EllipticCurve.Point.Point;
import utils.ElementCounter;

public class Message extends scheme.Components.Message {
    protected AdditivePoint m;

    public Message() {}

    @Override
    public final String TheoSize() {
        ElementCounter res = new ElementCounter();
        res.count((Point) m);
        return res.toString();
    }
}
