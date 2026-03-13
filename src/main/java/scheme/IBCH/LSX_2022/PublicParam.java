package scheme.IBCH.LSX_2022;

import EllipticCurve.Point.MultivePoint;
import scheme.Config;
import utils.ElementCounter;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class PublicParam extends scheme.Components.PublicParam implements scheme.IBCH.Components.PublicParam {
    protected MultivePoint g, g_1, g_2, egg, eg_2g;

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
    public final scheme.Components.Message createMessage(String msg) {
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
    public final scheme.Components.Identity createIdentity(String ID) {
        Identity res = new Identity();
        MessageDigest messageDigest;
        byte[] hash;
        try {
            messageDigest = MessageDigest.getInstance("SHA-256");
            messageDigest.update(ID.getBytes(StandardCharsets.UTF_8));
            hash = messageDigest.digest();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
        res.ID = curve.HashToZp(hash);
        return res;
    }

    @Override
    public final scheme.Components.MasterSecretKey createMasterSecretKey() {
        return new MasterSecretKey();
    }

    @Override
    public final scheme.Components.SecretKey createSecretKey() {
        return new SecretKey();
    }

    @Override
    public final scheme.Components.HashValue createHashValue() {
        return new HashValue();
    }

    @Override
    public final scheme.Components.Randomness createRandomness() {
        return new Randomness();
    }

}
