package Commitment.REPRESENT;

import EllipticCurve.Curve.Curve;
import EllipticCurve.Point.MultivePoint;
import EllipticCurve.Point.Scalar;
import utils.ElementCounter;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class Proof extends Commitment.Components.Proof<Proof, Witness> {
    protected Curve curve;
    public MultivePoint alpha;
    public Scalar gamma_1, gamma_2;

    protected Scalar H(String m) {
        byte[] hash;
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            hash = digest.digest(m.getBytes(StandardCharsets.UTF_8));
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
        alpha = o.alpha;
        gamma_1 = o.gamma_1;
        gamma_2 = o.gamma_2;
    }

    public final boolean Check(Witness data) {
        return data.g_1.pow(gamma_1).mul(data.g_2.pow(gamma_2)).div(alpha).isEqual(data.y.pow(H(String.format("%s|%s|%s|%s", data.y, data.g_1, data.g_2, alpha))));
    }
}
