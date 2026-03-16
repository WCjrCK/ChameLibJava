package Commitment.DH_PAIR;

import Commitment.NIZKConfig;
import EllipticCurve.Point.MultivePoint;
import EllipticCurve.Point.Scalar;

public class Scheme {
    public static Relation createRelation(Scalar x, MultivePoint u, MultivePoint g, MultivePoint v, MultivePoint h) {
        Relation res = new Relation();
        res.x = x;
        res.u = u;
        res.g = g;
        res.v = v;
        res.h = h;
        return res;
    }

    public static Proof Commitment(NIZKConfig config, Relation data) {
        if(!data.u.isEqual(data.g.pow(data.x))) throw new RuntimeException("输入数据不满足 u != g^x");
        if(!data.v.isEqual(data.h.pow(data.x))) throw new RuntimeException("输入数据不满足 v != h^x");
        Proof res = new Proof();
        res.curve = config.curve;
        res.s = config.curve.getRandomScalar();
        res.c = res.H(data.g, data.h, data.u, data.v, data.g.pow(res.s), data.h.pow(res.s));
        res.s = res.s.sub(res.c.mul(data.x));
        return res;
    }
}
