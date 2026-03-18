package ChameleonHash.CH.CHET.KOG_CDK_2017;

import EllipticCurve.Point.Scalar;
import utils.ElementCounter;

public class SecretKey extends ChameleonHash.CH.CHET.Components.SecretKey<SecretKey> {
    protected Scalar x;
    protected Encryption.PKE.Components.SecretKey pke_sk;

    @Override
    public void CopyFrom(SecretKey o) {
        x = o.x.copy();
        pke_sk.CopyFrom(o.pke_sk);
    }

    @Override
    public final ElementCounter TheoSize() {
        ElementCounter res = new ElementCounter();
        res.count(this);
        return res;
    }
}

