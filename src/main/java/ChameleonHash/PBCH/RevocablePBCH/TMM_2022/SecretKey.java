package ChameleonHash.PBCH.RevocablePBCH.TMM_2022;

import EllipticCurve.Point.Scalar;
import utils.ElementCounter;

public class SecretKey extends ChameleonHash.PBCH.RevocablePBCH.Components.SecretKey {
    Encryption.ABE.RevocableABE.TMM_2022.SecretKey RABE_sk;
    Scalar x;

    @Override
    public final ElementCounter TheoSize() {
        ElementCounter res = new ElementCounter();
        res.count(this);
        return res;
    }
}
