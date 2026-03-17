package ChameleonHash.CH.CHET.KOG_CDK_2017;

import ChameleonHash.CH.CHConfig;
import Commitment.NIZK_DL.Proof;
import Commitment.NIZK_DL.Scheme;
import EllipticCurve.Curve.CurveGroup;
import EllipticCurve.Point.MultivePoint;
import EllipticCurve.Point.Scalar;
import Encryption.PKE.PKE;
import Encryption.PKE.PKEConfig;
import Encryption.PKE.PKEFactory;
import utils.ElementCounter;
import utils.Serializer;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Objects;

public class PublicParam extends ChameleonHash.CH.CHET.Components.PublicParam<PublicKey, SecretKey, Message, ETrapdoor, HashValue, Randomness> {
    protected CurveGroup curveGroup;
    protected MultivePoint g;
    protected Scheme NIZK_DL;
    protected PKE PKEScheme;
    protected Encryption.PKE.Components.PublicParam pke_pp;

    public PublicParam(CHConfig config) {
        super(config.curveConfig);
        if (!config.params.containsKey("curve_group")) throw new IllegalArgumentException("未设置方案所在群（curve_group）");
        curveGroup = (CurveGroup) config.params.get("curve_group");
        if (curveGroup == CurveGroup.Zp) throw new IllegalArgumentException("方案未适配指定群： " + curveGroup);
        NIZK_DL = new Scheme(curve);
        PKEScheme = PKEFactory.createPKE((PKEConfig) Objects.requireNonNull(config.params.get("pke_config"), "未设置方案的黑盒公钥加密方案（pke_config）"));
        pke_pp = PKEScheme.createPublicParam(config.params);
    }

    @Override
    public final Message createMessage(String msg) {
        Message res = new Message();
        res.m = curve.HashToZp(hash(msg));
        return res;
    }

    public final Scalar H(Scalar m) {
        byte[] digest = hash(m.toString());
        return curve.HashToZp(digest);
    }

    @Override
    public final PublicKey createPublicKey() {
        PublicKey res =  new PublicKey();
        res.pke_pk = pke_pp.createPublicKey();
        return res;
    }

    @Override
    public final SecretKey createSecretKey() {
        SecretKey res = new SecretKey();
        res.pke_sk = pke_pp.createSecretKey();
        return res;
    }

    @Override
    public final HashValue createHashValue() {
        return new HashValue();
    }

    @Override
    public final Randomness createRandomness() {
        Randomness res = new Randomness();
        res.C = pke_pp.createCipherText();
        return res;
    }

    @Override
    public byte[] serializePublicKey(PublicKey target) {
        Objects.requireNonNull(target, "PublicKey 不能为空");
        return Serializer.pack(
                pointBytes(target.h),
                serializeProof(target.pi_pk),
                pke_pp.serializePublicKey(target.pke_pk)
        );
    }

    @Override
    public void deserializePublicKey(PublicKey target, byte[] data) {
        Objects.requireNonNull(target, "PublicKey 不能为空");
        Serializer.Reader reader = new Serializer.Reader(data);
        target.h = point(reader.readBytes(), curveGroup);
        target.pi_pk = deserializeProof(reader.readBytes());
        target.pke_pk = pke_pp.createPublicKey();
        pke_pp.deserializePublicKey(target.pke_pk, reader.readBytes());
        reader.ensureFullyConsumed();
    }

    @Override
    public byte[] serializeSecretKey(SecretKey target) {
        Objects.requireNonNull(target, "SecretKey 不能为空");
        return Serializer.pack(
                scalarBytes(target.x),
                pke_pp.serializeSecretKey(target.pke_sk)
        );
    }

    @Override
    public void deserializeSecretKey(SecretKey target, byte[] data) {
        Objects.requireNonNull(target, "SecretKey 不能为空");
        Serializer.Reader reader = new Serializer.Reader(data);
        target.x = scalar(reader.readBytes());
        target.pke_sk = pke_pp.createSecretKey();
        pke_pp.deserializeSecretKey(target.pke_sk, reader.readBytes());
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
        return Serializer.pack(
                pointBytes(target.b),
                pointBytes(target.h_p),
                serializeProof(target.pi_t)
        );
    }

    @Override
    public void deserializeHashValue(HashValue target, byte[] data) {
        Objects.requireNonNull(target, "HashValue 不能为空");
        Serializer.Reader reader = new Serializer.Reader(data);
        target.b = point(reader.readBytes(), curveGroup);
        target.h_p = point(reader.readBytes(), curveGroup);
        target.pi_t = deserializeProof(reader.readBytes());
        reader.ensureFullyConsumed();
    }

    @Override
    public byte[] serializeRandomness(Randomness target) {
        Objects.requireNonNull(target, "Randomness 不能为空");
        return Serializer.pack(
                pointBytes(target.p),
                pke_pp.serializeCipherText(target.C),
                serializeProof(asProof(target.pi_p))
        );
    }

    @Override
    public void deserializeRandomness(Randomness target, byte[] data) {
        Objects.requireNonNull(target, "Randomness 不能为空");
        Serializer.Reader reader = new Serializer.Reader(data);
        target.p = point(reader.readBytes(), curveGroup);
        target.C = pke_pp.createCipherText();
        pke_pp.deserializeCipherText(target.C, reader.readBytes());
        target.pi_p = deserializeProof(reader.readBytes());
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

    @Override
    public ETrapdoor createETrapdoor() {
        return new ETrapdoor();
    }

    @Override
    public byte[] serializeETrapdoor(ETrapdoor target) {
        Objects.requireNonNull(target, "ETrapdoor 不能为空");
        return Serializer.pack(scalarBytes(target.etd));
    }

    @Override
    public void deserializeETrapdoor(ETrapdoor target, byte[] data) {
        Objects.requireNonNull(target, "ETrapdoor 不能为空");
        Serializer.Reader reader = new Serializer.Reader(data);
        target.etd = scalar(reader.readBytes());
        reader.ensureFullyConsumed();
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

    private byte[] serializeProof(Proof proof) {
        Proof target = Objects.requireNonNull(proof, "证明不能为空");
        return Serializer.pack(pointBytes(target.alpha), scalarBytes(target.gamma));
    }

    private Proof deserializeProof(byte[] data) {
        Serializer.Reader reader = new Serializer.Reader(data);
        Proof proof = new Proof();
        proof.alpha = point(reader.readBytes(), curveGroup);
        proof.gamma = scalar(reader.readBytes());
        proof.bindCurve(curve);
        reader.ensureFullyConsumed();
        return proof;
    }

    private Proof asProof(Commitment.Components.Proof proof) {
        if (!(proof instanceof Proof)) {
            throw new IllegalArgumentException("仅支持 NIZK_DL.Proof");
        }
        return (Proof) proof;
    }
}
