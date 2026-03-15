package Encryption.ABE.FAME;

import EllipticCurve.Point.MultivePoint;
import Encryption.ABE.Components.Attributes;
import utils.ElementCounter;

import java.util.HashMap;

public class SecretKey extends Encryption.ABE.Components.SecretKey {
    protected HashMap<String, Integer> Attr2id;
    Attributes S;

    protected MultivePoint[][] sk_y;
    protected MultivePoint[] sk_p, sk_0;

    @Override
    public final ElementCounter TheoSize() {
        ElementCounter res = new ElementCounter();
        res.count(this);
        return res;
    }
}
