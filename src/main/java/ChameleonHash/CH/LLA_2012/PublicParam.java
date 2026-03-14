package ChameleonHash.CH.LLA_2012;

import ChameleonHash.Config;
import EllipticCurve.Curve.CurveGroup;
import EllipticCurve.Point.MultivePoint;
import EllipticCurve.Point.Scalar;
import utils.ElementCounter;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class PublicParam
        extends ChameleonHash.CH.Components.PublicParam<PublicKey, SecretKey, Message, HashValue, Randomness> {
    public CurveGroup curveGroup;

    public PublicParam(Config config) {
        super(config.curveConfig);
        if (!config.params.containsKey("curve_group")) throw new IllegalArgumentException("未设置方案所在群（curve_group）");
        curveGroup = (CurveGroup) config.params.get("curve_group");
        if(curveGroup != CurveGroup.G1 && curveGroup != CurveGroup.G2 && curveGroup != CurveGroup.GT) throw new IllegalArgumentException("方案未适配指定群： " + curveGroup);
    }

    @Override
    public final String toString() {
        return "";
    }

    public final Scalar H1(MultivePoint m1, MultivePoint m2, MultivePoint m3) {
        MessageDigest messageDigest;
        byte[] hash;
        try {
            messageDigest = MessageDigest.getInstance("SHA-256");
            messageDigest.update(String.format("%s|%s|%s", m1, m2, m3).getBytes(StandardCharsets.UTF_8));
            hash = messageDigest.digest();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
        return curve.HashToZp(hash);
    }

    public final Scalar H2(MultivePoint m1) {
        MessageDigest messageDigest;
        byte[] hash;
        try {
            messageDigest = MessageDigest.getInstance("SHA-256");
            messageDigest.update(m1.toString().getBytes(StandardCharsets.UTF_8));
            hash = messageDigest.digest();
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
    public final Message createMessage(String msg) {
        Message res = new Message();
        MessageDigest messageDigest;
        byte[] hash;
        try {
            messageDigest = MessageDigest.getInstance("SHA-256");
            messageDigest.update(msg.getBytes(StandardCharsets.UTF_8));
            hash = messageDigest.digest();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
        res.m = curve.HashToZp(hash);
        return res;
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

}
