package ChameleonHash.CH.BaseCH.DSS_2020;

import EllipticCurve.Point.MultivePoint;
import utils.ElementCounter;

public class Message extends ChameleonHash.CH.Components.Message {
    protected MultivePoint m;

    @Override
    public final ElementCounter TheoSize() {
        ElementCounter res = new ElementCounter();
        res.count(this);
        return res;
    }
}

