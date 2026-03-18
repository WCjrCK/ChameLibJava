package ChameleonHash.PBCH.BAPBCH.TLL_2020;

import EllipticCurve.Point.Scalar;
import utils.ElementCounter;

public class Message extends ChameleonHash.PBCH.BasePBCH.Components.Message {
    protected Scalar m;

    @Override
    public final ElementCounter TheoSize() {
        ElementCounter res = new ElementCounter();
        res.count(this);
        return res;
    }
}
