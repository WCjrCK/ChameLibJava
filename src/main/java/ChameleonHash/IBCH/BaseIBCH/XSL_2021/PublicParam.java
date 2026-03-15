package ChameleonHash.IBCH.BaseIBCH.XSL_2021;

import ChameleonHash.Config;
import EllipticCurve.Point.MultivePoint;
import utils.ElementCounter;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.BitSet;

public class PublicParam
        extends ChameleonHash.IBCH.Components.PublicParam<MasterSecretKey, SecretKey, Message, Identity, HashValue, Randomness> {
    protected MultivePoint g, g_1, g_2;
    protected MultivePoint[] u;
    int n;

    public PublicParam(Config config) {
        super(config.curveConfig);
        if (!config.params.containsKey("ID_Binary_Len")) throw new IllegalArgumentException("需要指定身份标识的二进制长度（ID_Binary_Len）");
        n = (int) config.params.get("ID_Binary_Len");
        u = new MultivePoint[n + 1];
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
        byte[] hash = ID.getBytes(StandardCharsets.UTF_8);
        res.I = new BitSet(n);
        for(int i = 0;i < n;) {
            try {
                messageDigest = MessageDigest.getInstance("SHA-256");
                messageDigest.update(hash);
                hash = messageDigest.digest();
                for (int j = 0; j < hash.length * 8 && i + j < n; j++) {
                    if ((hash[hash.length - j / 8 - 1] & (1 << (j % 8))) > 0) res.I.set(i + j);
                }
            } catch (NoSuchAlgorithmException e) {
                throw new RuntimeException(e);
            }
            i += hash.length * 8;
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

}
