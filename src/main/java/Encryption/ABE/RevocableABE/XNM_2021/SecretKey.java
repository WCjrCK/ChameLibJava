package Encryption.ABE.RevocableABE.XNM_2021;

import EllipticCurve.Point.MultivePoint;
import utils.ElementCounter;

import java.util.HashMap;

public class SecretKey extends Encryption.ABE.RevocableABE.Components.SecretKey {
    protected Encryption.ABE.BaseABE.FAME.SecretKey FAME_sk;
    protected HashMap<Integer, MultivePoint> sk_theta = new HashMap<>();
    int node_id;

    @Override
    public final ElementCounter TheoSize() {
        ElementCounter res = new ElementCounter();
        res.count(this);
        return res;
    }
}
