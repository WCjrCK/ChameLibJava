package ChameleonHash.PBCH.RevocablePBCH.TMM_2022;

import EllipticCurve.Point.MultivePoint;
import utils.ElementCounter;

public class PublicKey extends ChameleonHash.PBCH.RevocablePBCH.Components.PublicKey {
    MultivePoint pk;

    @Override
    public final ElementCounter TheoSize() {
        ElementCounter res = new ElementCounter();
        res.count(this);
        return res;
    }
}
