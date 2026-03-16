package ChameleonHash.CH.BaseCH.DKS_2020;

import ChameleonHash.CH.CHConfig;
import EllipticCurve.Curve.CurveGroup;
import EllipticCurve.Point.MultivePoint;
import EllipticCurve.Point.Point;
import EllipticCurve.Point.Scalar;
import utils.ElementCounter;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class PublicParam extends ChameleonHash.CH.Components.PublicParam<PublicKey, SecretKey, Message, HashValue, Randomness> {
    protected CurveGroup curveGroup;
    protected MultivePoint g_1, g_2;

    public PublicParam(CHConfig config) {
        super(config.curveConfig);
        if (!config.params.containsKey("curve_group")) throw new IllegalArgumentException("未设置方案所在群（curve_group）");
        curveGroup = (CurveGroup) config.params.get("curve_group");
        if (curveGroup == CurveGroup.Zp) throw new IllegalArgumentException("方案未适配指定群： " + curveGroup);
    }

    @Override
    public final Message createMessage(String msg) {
        Message res = new Message();
        res.m = curve.HashToZp(hash(msg));
        return res;
    }

    public final Scalar H(MultivePoint m1, MultivePoint m2, Scalar m3, MultivePoint m4, MultivePoint m5) {
        byte[] digest = hash(String.format("(%s|%s|%s)(%s|%s)", m1, m2, m3, curve.PowNdonr((Point) m4), curve.PowNdonr((Point) m5)));
        return curve.HashToZp(digest);
    }

    public final MultivePoint H_p(MultivePoint m1) {
        byte[] digest = hash(String.format("%s", m1));
        switch (curveGroup) {
            case G1:
                return curve.HashToG1(digest);
            case G2:
                return curve.HashToG2(digest);
            case GT:
                return curve.HashToGT(digest);
            default:
                throw new IllegalArgumentException("方案未适配指定群： " + curveGroup);
        }
    }

    @Override
    public final PublicKey createPublicKey() {
        return new PublicKey();
    }

    @Override
    public final SecretKey createSecretKey() {
        return new SecretKey();
    }

    @Override
    public final HashValue createHashValue() {
        return new HashValue();
    }

    @Override
    public final Randomness createRandomness() {
        return new Randomness();
    }

    @Override
    public final String toString() {
        return "";
    }

    @Override
    public final ElementCounter TheoSize() {
        ElementCounter res = new ElementCounter();
        res.count(this);
        return res;
    }

    private byte[] hash(String input) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return digest.digest(input.getBytes(StandardCharsets.UTF_8));
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }
}

