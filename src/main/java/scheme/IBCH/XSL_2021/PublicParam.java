package scheme.IBCH.XSL_2021;

import EllipticCurve.Curve.CurveName;
import EllipticCurve.Point.MultivePoint;
import EllipticCurve.Point.PointRepresentation;
import utils.ElementCounter;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.BitSet;
import java.util.Map;
import java.util.Random;

public class PublicParam extends scheme.Components.PublicParam implements scheme.IBCH.Components.PublicParam {
    protected MultivePoint g, g_1, g_2;
    protected MultivePoint[] u;
    int n;

    public PublicParam(CurveName curveName, Map<String, Object> params) {
        super(curveName, PointRepresentation.MULTIVE, params);
        if (!params.containsKey("ID_Binary_Len")) throw new IllegalArgumentException("需要指定身份标识的二进制长度（ID_Binary_Len）");
        n = (int) params.get("ID_Binary_Len");
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
        ByteBuffer buffer = ByteBuffer.wrap(hash);
        buffer.order(ByteOrder.BIG_ENDIAN); // 或 ByteOrder.LITTLE_ENDIAN
        Random rand = new Random();
        rand.setSeed(buffer.getLong());
        res.I = new BitSet(n);
        for(int i = 0;i < n;++i) res.I.set(i, rand.nextBoolean());
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
