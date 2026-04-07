package ChameleonHash.IBCH.BaseIBCH.ZSS_2003;

import ChameleonHash.IBCH.IBCHConfig;
import EllipticCurve.Point.AdditivePoint;
import EllipticCurve.Point.Scalar;
import utils.ElementCounter;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class PublicParam
        extends ChameleonHash.IBCH.BaseIBCH.Components.PublicParam<MasterSecretKey, SecretKey, Message, Identity, HashValue, Randomness> {
    protected AdditivePoint P;
    protected AdditivePoint P_pub;
    protected AdditivePoint p;

    public PublicParam(IBCHConfig config) {
        super(config.curveConfig);
    }

    @Override
    public final String toString() {
        return "P = " + P.toString() + " | P_pub = " + P_pub.toString();
    }

    public final AdditivePoint H0(String x) {
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

    public final Scalar H1(String x) {
        MessageDigest messageDigest;
        byte[] hash;
        try {
            messageDigest = MessageDigest.getInstance("SHA-256");
            messageDigest.update(x.getBytes(StandardCharsets.UTF_8));
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
        return new Message(msg);
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
