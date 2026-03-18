package ChameleonHash.CH.LabelCH.CZK_2004;

import EllipticCurve.Point.Scalar;
import utils.ElementCounter;

public class Message extends ChameleonHash.CH.LabelCH.Components.Message {
    protected Scalar m;

    @Override
    public final ElementCounter TheoSize() {
        ElementCounter res = new ElementCounter();
        res.count(this);
        return res;
    }
}

