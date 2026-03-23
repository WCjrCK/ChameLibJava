package ChameleonHash.PBCH.RevocablePBCH.TMM_2022;

import EllipticCurve.Point.MultivePoint;
import Encryption.ABE.RevocableABE.TMM_2022.CipherText;
import utils.ElementCounter;

public class HashValue extends ChameleonHash.PBCH.RevocablePBCH.Components.HashValue<HashValue> {
    CipherText RABE_ct;
    MultivePoint b, h;

    @Override
    public boolean isEqual(HashValue other) {
        return RABE_ct.isEqual(other.RABE_ct) && b.isEqual(other.b) && h.isEqual(other.h);
    }

    @Override
    public final ElementCounter TheoSize() {
        ElementCounter res = new ElementCounter();
        res.count(this);
        return res;
    }
}
