package Encryption.ABE.BaseABE.FAME;

import EllipticCurve.Point.MultivePoint;
import Encryption.ABE.Components.Attributes;
import utils.ElementCounter;

import java.util.HashMap;

public class SecretKey extends Encryption.ABE.Components.SecretKey {
    protected HashMap<String, Integer> Attr2id;
    Attributes S;

    protected MultivePoint[][] sk_y;
    public MultivePoint[] sk_p;
    protected MultivePoint[] sk_0;

    public final void CopyFrom(SecretKey o) {
        Attr2id = new HashMap<>(o.Attr2id);
        S.CopyFrom(o.S);
        sk_y = new MultivePoint[o.sk_y.length][o.sk_y[0].length];
        for (int i = 0; i < o.sk_y.length; i++) for (int j = 0;j < o.sk_y[i].length; ++j) sk_y[i][j] = o.sk_y[i][j].copy();

        sk_0 = new MultivePoint[o.sk_0.length];
        for (int i = 0; i < o.sk_0.length; i++) sk_0[i] = o.sk_0[i].copy();
        sk_p = new MultivePoint[o.sk_p.length];
        for (int i = 0; i < o.sk_p.length; i++) sk_p[i] = o.sk_p[i].copy();
    }

    @Override
    public final ElementCounter TheoSize() {
        ElementCounter res = new ElementCounter();
        res.count(this);
        return res;
    }
}
