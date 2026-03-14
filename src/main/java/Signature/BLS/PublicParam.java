package Signature.BLS;

import EllipticCurve.Curve.Curve;
import EllipticCurve.Curve.CurveFactory;
import EllipticCurve.Point.MultivePoint;
import Signature.Config;
import utils.ElementCounter;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class PublicParam
        extends Signature.Components.PublicParam<PublicKey, SecretKey, Message, SignValue> {
    protected MultivePoint g;

    public Curve curve;

    protected PublicParam(Config config) {
        curve = CurveFactory.create(config.curveConfig);
    }

    public final MultivePoint H(String x) {
        MessageDigest messageDigest;
        byte[] hash;
        try {
            messageDigest = MessageDigest.getInstance("SHA-256");
            messageDigest.update(x.getBytes(StandardCharsets.UTF_8));
            hash = messageDigest.digest();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
        return curve.HashToG1(hash);
    }

    @Override
    public final ElementCounter TheoSize() {
        ElementCounter res = new ElementCounter();
        res.count(this);
        return res;
    }

    @Override
    public final Message createMessage(String msg) {
        return new Message(msg);
    }

    @Override
    public final SecretKey createSecretKey() {
        return new SecretKey();
    }

    @Override
    public final PublicKey createPublicKey() {
        return new PublicKey();
    }

    @Override
    public final SignValue createSignValue() {
        return new SignValue();
    }

}
