package scheme.IBCH.CZS_2014;

import EllipticCurve.Point.AdditivePoint;
import scheme.Config;
import utils.ElementCounter;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class PublicParam
        extends scheme.IBCH.Components.PublicParam<MasterSecretKey, SecretKey, Identity, Message, HashValue, Randomness> {
    protected AdditivePoint P, P_pub;

    public PublicParam(Config config) {
        super(config.curveConfig);
    }

    @Override
    public final String toString() {
        return "P = " + P.toString() + " | P_pub = " + P_pub.toString();
    }

    public final AdditivePoint H(String x) {
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

    public final AdditivePoint H_p(String x) {
        MessageDigest messageDigest;
        byte[] hash;
        try {
            messageDigest = MessageDigest.getInstance("SHA-256");
            messageDigest.update(x.getBytes(StandardCharsets.UTF_8));
            hash = messageDigest.digest();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
        return curve.HashToG2(hash);
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
    public final Identity createIdentity(String ID) {
        return new Identity(ID);
    }

    @Override
    public final MasterSecretKey createMasterSecretKey() {
        return new MasterSecretKey();
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
