package ChameleonHash.IBCH.LabelIBCH.LJF_2025;

import ChameleonHash.IBCH.IBCHConfig;
import EllipticCurve.Point.MultivePoint;
import utils.ElementCounter;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class PublicParam extends ChameleonHash.IBCH.LabelIBCH.Components.PublicParam<MasterSecretKey, SecretKey, Message, Identity, Label, HashValue, Randomness> {
    protected MultivePoint g, g_1, g_2, h_2, u_2, egg, eg_2g;

    public PublicParam(IBCHConfig config) {
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

    @Override
    public final Identity createIdentity(String ID) {
        Identity res = new Identity();
        MessageDigest messageDigest;
        byte[] hash;
        try {
            messageDigest = MessageDigest.getInstance("SHA-256");
            messageDigest.update(ID.getBytes(StandardCharsets.UTF_8));
            hash = messageDigest.digest();
            res.ID = curve.HashToZp(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
        return res;
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

    @Override
    public Label createLabel(String L) {
        Label res = new Label();
        MessageDigest messageDigest;
        byte[] hash;
        try {
            messageDigest = MessageDigest.getInstance("SHA-256");
            messageDigest.update(L.getBytes(StandardCharsets.UTF_8));
            hash = messageDigest.digest();
            res.L = curve.HashToZp(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
        return res;
    }
}
