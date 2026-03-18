package ChameleonHash.CH.BaseCH.DKS_2020;

import EllipticCurve.Point.Scalar;
import utils.ElementCounter;

public class Message extends ChameleonHash.CH.BaseCH.Components.Message {
    protected Scalar m;

    @Override
    public final ElementCounter TheoSize() {
        ElementCounter res = new ElementCounter();
        res.count(this);
        return res;
    }
}

