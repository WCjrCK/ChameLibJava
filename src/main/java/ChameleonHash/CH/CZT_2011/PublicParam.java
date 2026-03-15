package ChameleonHash.CH.CZT_2011;

import ChameleonHash.Config;
import EllipticCurve.Curve.CurveGroup;
import EllipticCurve.Point.MultivePoint;
import utils.ElementCounter;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class PublicParam extends ChameleonHash.CH.Components.PublicParam<PublicKey, SecretKey, Message, HashValue, Randomness> {
    protected final CurveGroup curveGroup;
    protected MultivePoint g;

    public PublicParam(Config config) {
        super(config.curveConfig);
        if (!config.params.containsKey("curve_group")) throw new IllegalArgumentException("未设置方案所在群（curve_group）");
        curveGroup = (CurveGroup) config.params.get("curve_group");
        if (curveGroup == CurveGroup.Zp) throw new IllegalArgumentException("方案未适配指定群： " + curveGroup);
    }

    public final Message createMessage(String msg, String I) {
        Message res = new Message();
        res.m = curve.HashToZp(msg.getBytes());
        res.I = I;
        return res;
    }

    @Override
    public final Message createMessage(String msg) {
        return createMessage(msg, msg);
    }

    public final MultivePoint H(MultivePoint m1, String m2) {
        String toHash = m1.toString() + "|" + m2;
        byte[] res = toHash.getBytes(StandardCharsets.UTF_8);
        try {
            MessageDigest messageDigest;
            messageDigest = MessageDigest.getInstance("SHA-256");
            messageDigest.update(res);
            res = messageDigest.digest();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
        switch (curveGroup) {
            case G1: return curve.HashToG1(res);
            case G2: return curve.HashToG2(res);
            case GT: return curve.HashToGT(res);
            default: throw new IllegalArgumentException("方案未适配指定群： " + curveGroup);
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
        return "g = " + g;
    }

    @Override
    public final ElementCounter TheoSize() {
        ElementCounter res = new ElementCounter();
        res.count(this);
        return res;
    }
}

