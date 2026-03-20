package Commitment.NIZK_DL;

import EllipticCurve.Curve.Curve;
import EllipticCurve.Point.MultivePoint;
import EllipticCurve.Point.Scalar;

//Schnorr Non-interactive Zero-Knowledge Proof

public class Scheme implements Commitment.Interface.NIZK_DL<Proof, Witness> {
    protected Curve curve;

    public Scheme(Curve curve) {
        this.curve = curve;
    }

    @Override
    public final Witness createRelation(MultivePoint g, MultivePoint y) {
        Witness res = new Witness();
        res.g = g;
        res.y = y;
        return res;
    }

    @Override
    public final Witness createRelation(Scalar x, MultivePoint g, MultivePoint y) {
        Witness res = new Witness();
        res.x = x;
        res.g = g;
        res.y = y;
        return res;
    }

    @Override
    public final Proof Prove(Witness data) {
        if(!data.g.pow(data.x).isEqual(data.y)) throw new RuntimeException("输入数据不满足 g^x == y");
        Proof res = new Proof();
        res.curve = curve;
        res.gamma = curve.getRandomScalar();
        res.alpha = data.g.pow(res.gamma);
        res.gamma = res.H(String.format("%s|%s", data.y, res.alpha)).mul(data.x).add(res.gamma);
        return res;
    }
}
