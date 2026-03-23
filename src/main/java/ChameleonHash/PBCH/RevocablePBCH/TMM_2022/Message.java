package ChameleonHash.PBCH.RevocablePBCH.TMM_2022;

import EllipticCurve.Point.Scalar;
import utils.ElementCounter;

public class Message extends ChameleonHash.PBCH.RevocablePBCH.Components.Message {
    Scalar m;

    @Override
    public final ElementCounter TheoSize() {
        ElementCounter res = new ElementCounter();
        res.count(this);
        return res;
    }
}
