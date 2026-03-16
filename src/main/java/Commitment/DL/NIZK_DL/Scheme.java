package Commitment.DL.NIZK_DL;

import EllipticCurve.Point.MultivePoint;
import EllipticCurve.Point.Scalar;

public class Scheme extends Commitment.NIZK<Proof, Relation> implements Commitment.Interface.NIZK_DL<Proof, Relation> {
    @Override
    public final Relation createRelation(MultivePoint g, MultivePoint y) {
        Relation res = new Relation();
        res.g = g;
        res.y = y;
        return res;
    }

    @Override
    public final Relation createRelation(Scalar x, MultivePoint g, MultivePoint y) {
        Relation res = new Relation();
        res.x = x;
        res.g = g;
        res.y = y;
        return res;
    }

    @Override
    public final Proof Commitment(Relation data) {
        if(!data.g.pow(data.x).isEqual(data.y)) throw new RuntimeException("输入数据不满足 g^x == y");
        Proof res = new Proof();
        res.curve = curve;
        res.gamma = curve.getRandomScalar();
        res.alpha = data.g.pow(res.gamma);
        res.gamma = res.H(String.format("%s|%s", data.y, res.alpha)).mul(data.x).add(res.gamma);
        return res;
    }
}
