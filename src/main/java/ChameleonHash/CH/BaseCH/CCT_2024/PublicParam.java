package ChameleonHash.CH.BaseCH.CCT_2024;

import ChameleonHash.CH.CHConfig;
import EllipticCurve.Curve.CurveGroup;
import EllipticCurve.Point.MultivePoint;
import EllipticCurve.Point.Point;
import EllipticCurve.Point.Scalar;
import utils.ElementCounter;
import utils.Serializer;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Objects;

public class PublicParam extends ChameleonHash.CH.Components.PublicParam<PublicKey, SecretKey, Message, HashValue, Randomness> {
    protected CurveGroup curveGroup;
    protected MultivePoint g;

    public PublicParam(CHConfig config) {
        super(config.curveConfig);
        if (!config.params.containsKey("curve_group")) throw new IllegalArgumentException("未设置方案所在群（curve_group）");
        curveGroup = (CurveGroup) config.params.get("curve_group");
        if (curveGroup == CurveGroup.Zp) throw new IllegalArgumentException("方案未适配指定群： " + curveGroup);
    }

    @Override
    public final Message createMessage(String msg) {
        Message res = new Message();
        res.m = curve.HashToZp(hash(msg));
        return res;
    }

    public final MultivePoint H(Scalar m) {
        byte[] digest = hash(m.toString());
        switch (curveGroup) {
            case G1:
                return curve.HashToG1(digest);
            case G2:
                return curve.HashToG2(digest);
            case GT:
                return curve.HashToGT(digest);
            default:
                throw new IllegalArgumentException("方案未适配指定群： " + curveGroup);
        }
    }

    public final Scalar H_p(MultivePoint m1, MultivePoint m2, MultivePoint m3, Scalar m4) {
        return curve.HashToZp(hash(String.format("%s|%s|%s|%s", curve.PowNdonr((Point) m1), m2, m3, m4)));
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
    public byte[] serializePublicKey(PublicKey target) {
        Objects.requireNonNull(target, "PublicKey 不能为空");
        return Serializer.pack(pointBytes(target.g_x));
    }

    @Override
    public void deserializePublicKey(PublicKey target, byte[] data) {
        Objects.requireNonNull(target, "PublicKey 不能为空");
        Serializer.Reader reader = new Serializer.Reader(data);
        target.g_x = point(reader.readBytes(), curveGroup);
        reader.ensureFullyConsumed();
    }

    @Override
    public byte[] serializeSecretKey(SecretKey target) {
        Objects.requireNonNull(target, "SecretKey 不能为空");
        return Serializer.pack(scalarBytes(target.x));
    }

    @Override
    public void deserializeSecretKey(SecretKey target, byte[] data) {
        Objects.requireNonNull(target, "SecretKey 不能为空");
        Serializer.Reader reader = new Serializer.Reader(data);
        target.x = scalar(reader.readBytes());
        reader.ensureFullyConsumed();
    }

    @Override
    public byte[] serializeMessage(Message target) {
        Objects.requireNonNull(target, "Message 不能为空");
        return Serializer.pack(scalarBytes(target.m));
    }

    @Override
    public void deserializeMessage(Message target, byte[] data) {
        Objects.requireNonNull(target, "Message 不能为空");
        Serializer.Reader reader = new Serializer.Reader(data);
        target.m = scalar(reader.readBytes());
        reader.ensureFullyConsumed();
    }

    @Override
    public byte[] serializeHashValue(HashValue target) {
        Objects.requireNonNull(target, "HashValue 不能为空");
        return Serializer.pack(pointBytes(target.h));
    }

    @Override
    public void deserializeHashValue(HashValue target, byte[] data) {
        Objects.requireNonNull(target, "HashValue 不能为空");
        Serializer.Reader reader = new Serializer.Reader(data);
        target.h = point(reader.readBytes(), curveGroup);
        reader.ensureFullyConsumed();
    }

    @Override
    public byte[] serializeRandomness(Randomness target) {
        Objects.requireNonNull(target, "Randomness 不能为空");
        return Serializer.pack(
                scalarBytes(target.z_1),
                scalarBytes(target.z_2),
                scalarBytes(target.c_1)
        );
    }

    @Override
    public void deserializeRandomness(Randomness target, byte[] data) {
        Objects.requireNonNull(target, "Randomness 不能为空");
        Serializer.Reader reader = new Serializer.Reader(data);
        target.z_1 = scalar(reader.readBytes());
        target.z_2 = scalar(reader.readBytes());
        target.c_1 = scalar(reader.readBytes());
        reader.ensureFullyConsumed();
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

    private byte[] hash(String input) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return digest.digest(input.getBytes(StandardCharsets.UTF_8));
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    private byte[] pointBytes(MultivePoint point) {
        return Objects.requireNonNull(point, "点字段不能为空").toBytes();
    }

    private byte[] scalarBytes(Scalar scalar) {
        return Objects.requireNonNull(scalar, "标量字段不能为空").toBytes();
    }

    private MultivePoint point(byte[] data, CurveGroup group) {
        return (MultivePoint) curve.createPointFromBytes(group, data);
    }

    private Scalar scalar(byte[] data) {
        return curve.createScalarFromBytes(data);
    }
}
