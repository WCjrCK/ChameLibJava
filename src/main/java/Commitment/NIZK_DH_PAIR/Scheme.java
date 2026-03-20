package Commitment.NIZK_DH_PAIR;

import Commitment.Interface.NIZK_DH_PAIR;
import EllipticCurve.Curve.Curve;
import EllipticCurve.Point.MultivePoint;
import EllipticCurve.Point.Scalar;

public class Scheme implements NIZK_DH_PAIR<Proof, Witness> {
    protected Curve curve;

    public Scheme(Curve curve) {
        this.curve = curve;
    }

    @Override
    public final Witness createRelation(Scalar x, MultivePoint g, MultivePoint u, MultivePoint h, MultivePoint v) {
        Witness res = new Witness();
        res.x = x;
        res.u = u;
        res.g = g;
        res.v = v;
        res.h = h;
        return res;
    }

    @Override
    public final Witness createRelation(MultivePoint g, MultivePoint u, MultivePoint h, MultivePoint v) {
        Witness res = new Witness();
        res.u = u;
        res.g = g;
        res.v = v;
        res.h = h;
        return res;
    }

    @Override
    public final Proof Prove(Witness data) {
        if(!data.u.isEqual(data.g.pow(data.x))) throw new RuntimeException("输入数据不满足 u != g^x");
        if(!data.v.isEqual(data.h.pow(data.x))) throw new RuntimeException("输入数据不满足 v != h^x");
        Proof res = new Proof();
        res.curve = curve;
        res.s = curve.getRandomScalar();
        res.c = res.H(data.g, data.h, data.u, data.v, data.g.pow(res.s), data.h.pow(res.s));
        res.s = res.s.sub(res.c.mul(data.x));
        return res;
    }
}
