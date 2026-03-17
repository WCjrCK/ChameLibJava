package Encryption.ABE.BaseABE.FAME;

import EllipticCurve.Curve.CurveGroup;
import EllipticCurve.Point.MultivePoint;
import Encryption.ABE.ABEConfig;
import Encryption.ABE.Components.Attributes;
import Encryption.ABE.utils.BooleanFormulaParser;
import utils.ElementCounter;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class PublicParam extends Encryption.ABE.Components.PublicParam<
        MasterPublicKey,
        MasterSecretKey,
        SecretKey,
        PlainText,
        CipherText> {
    protected PublicParam(ABEConfig abeConfig) {
        super(abeConfig);
    }

    @Override
    public Attributes createAttributes() {
        return new Attributes();
    }

    @Override
    public Policy createPolicy(String BooleanFormulas) {
        Policy res = new Policy();
        BooleanFormulaParser.parse(res.MSP, curve, BooleanFormulas);
        return res;
    }

    @Override
    public MasterPublicKey createMasterPublicKey() {
        return new MasterPublicKey();
    }

    @Override
    public MasterSecretKey createMasterSecretKey() {
        return new MasterSecretKey();
    }

    @Override
    public SecretKey createSecretKey() {
        SecretKey res = new SecretKey();
        res.sk_p = new MultivePoint[]{curve.getRandomPoint(CurveGroup.G1), curve.getRandomPoint(CurveGroup.G1), curve.getRandomPoint(CurveGroup.G1)};
        res.sk_0 = new MultivePoint[]{curve.getRandomPoint(CurveGroup.G2), curve.getRandomPoint(CurveGroup.G2), curve.getRandomPoint(CurveGroup.G2)};
        res.S = createAttributes();
        return res;
    }

    @Override
    public PlainText createPlainText(String msg) {
        PlainText res = new PlainText();
        MessageDigest messageDigest;
        byte[] hash;
        try {
            messageDigest = MessageDigest.getInstance("SHA-256");
            messageDigest.update(msg.getBytes(StandardCharsets.UTF_8));
            hash = messageDigest.digest();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
        res.m = curve.HashToGT(hash);
        return res;
    }

    @Override
    public CipherText createCipherText() {
        CipherText res = new CipherText();
        res.ct_0 = new MultivePoint[]{curve.getRandomPoint(CurveGroup.G2), curve.getRandomPoint(CurveGroup.G2), curve.getRandomPoint(CurveGroup.G2)};
        return res;
    }

    public final MultivePoint H(String m) {
        MessageDigest messageDigest;
        byte[] hash;
        try {
            messageDigest = MessageDigest.getInstance("SHA-256");
            messageDigest.update(m.getBytes(StandardCharsets.UTF_8));
            hash = messageDigest.digest();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
        return curve.HashToG1(hash);
    }

    @Override
    public final ElementCounter TheoSize() {
        ElementCounter res = new ElementCounter();
        res.count(this);
        return res;
    }
}
