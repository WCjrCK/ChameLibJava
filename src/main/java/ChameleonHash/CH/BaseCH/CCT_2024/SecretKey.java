package ChameleonHash.CH.BaseCH.CCT_2024;

import EllipticCurve.Point.Scalar;
import utils.ElementCounter;

public class SecretKey extends ChameleonHash.CH.BaseCH.Components.SecretKey<SecretKey> {
    protected Scalar x;

    @Override
    public void CopyFrom(SecretKey o) {
        x = o.x.copy();
    }

    @Override
    public final ElementCounter TheoSize() {
        ElementCounter res = new ElementCounter();
        res.count(this);
        return res;
    }
}

