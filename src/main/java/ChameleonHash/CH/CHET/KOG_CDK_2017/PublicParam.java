package ChameleonHash.CH.CHET.KOG_CDK_2017;

import ChameleonHash.CH.CHConfig;
import Commitment.NIZK_DL.Scheme;
import EllipticCurve.Curve.CurveGroup;
import EllipticCurve.Point.MultivePoint;
import EllipticCurve.Point.Scalar;
import Encryption.PKE.PKE;
import Encryption.PKE.PKEConfig;
import Encryption.PKE.PKEFactory;
import utils.ElementCounter;

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
}

