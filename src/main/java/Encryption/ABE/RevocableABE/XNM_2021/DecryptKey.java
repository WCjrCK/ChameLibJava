package Encryption.ABE.RevocableABE.XNM_2021;

import EllipticCurve.Point.MultivePoint;
import Encryption.ABE.BaseABE.FAME.SecretKey;
import utils.ElementCounter;

public class DecryptKey extends Encryption.ABE.RevocableABE.Components.DecryptKey<Info> {
    protected int node_id;
    protected SecretKey FAME_sk;
    protected MultivePoint sk_0_4;

    protected final void CopyFromSK(Encryption.ABE.RevocableABE.XNM_2021.SecretKey sk) {
        FAME_sk.CopyFrom(sk.FAME_sk);
    }

    @Override
    public final ElementCounter TheoSize() {
        ElementCounter res = new ElementCounter();
        res.count(this);
        return res;
    }
}
