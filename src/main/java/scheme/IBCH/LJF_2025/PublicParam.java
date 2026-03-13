package scheme.IBCH.LJF_2025;

import EllipticCurve.Point.MultivePoint;
import scheme.Config;
import utils.ElementCounter;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class PublicParam extends scheme.IBCH.Components.PublicParam<MasterSecretKey, SecretKey, Identity, Message, HashValue, Randomness> {
    protected MultivePoint g, g_1, g_2, h_2, u_2, egg, eg_2g;

    public PublicParam(Config config) {
        super(config.curveConfig);
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

    public final Identity createIdentity(String ID, String L) {
        Identity res = new Identity();
        MessageDigest messageDigest;
        byte[] hash;
        try {
            messageDigest = MessageDigest.getInstance("SHA-256");
            messageDigest.update(ID.getBytes(StandardCharsets.UTF_8));
            hash = messageDigest.digest();
            res.ID = curve.HashToZp(hash);
            messageDigest = MessageDigest.getInstance("SHA-256");
            messageDigest.update(L.getBytes(StandardCharsets.UTF_8));
            hash = messageDigest.digest();
            res.L = curve.HashToZp(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
        return res;
    }

    public final void resetLabel(Identity ID, String L) {
        MessageDigest messageDigest;
        byte[] hash;
        try {
            messageDigest = MessageDigest.getInstance("SHA-256");
            messageDigest.update(L.getBytes(StandardCharsets.UTF_8));
            hash = messageDigest.digest();
            ID.L = curve.HashToZp(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public final Identity createIdentity(String ID) {
        return createIdentity(ID, ID);
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
