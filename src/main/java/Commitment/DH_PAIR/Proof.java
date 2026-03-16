package Commitment.DH_PAIR;

import EllipticCurve.Curve.Curve;
import EllipticCurve.Point.MultivePoint;
import EllipticCurve.Point.Point;
import EllipticCurve.Point.Scalar;
import utils.ElementCounter;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class Proof extends Commitment.Components.Proof<Proof, Relation> {
    protected Curve curve;
    public Scalar s, c;

    protected Scalar H(MultivePoint m1, MultivePoint m2, MultivePoint m3, MultivePoint m4, MultivePoint m5, MultivePoint m6) {
        byte[] hash;
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            hash = digest.digest(String.format("%s|%s|%s|%s|%s|%s", m1, m2, m3, m4, curve.PowNdonr((Point) m5), curve.PowNdonr((Point) m6)).getBytes(StandardCharsets.UTF_8));
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
        return curve.HashToZp(hash);
    }

    @Override
    public final ElementCounter TheoSize() {
        ElementCounter res = new ElementCounter();
        res.count(this);
        return res;
    }

    @Override
    public void CopyFrom(Proof o) {
        curve = o.curve;
        s = o.s;
        c = o.c;
    }

    public final boolean Check(Relation data) {
        return c.isEqual(H(data.g, data.h, data.u, data.v, data.g.pow(s).mul(data.u.pow(c)), data.h.pow(s).mul(data.v.pow(c))));
    }
}
