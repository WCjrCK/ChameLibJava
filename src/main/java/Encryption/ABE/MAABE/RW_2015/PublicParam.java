package Encryption.ABE.MAABE.RW_2015;

import EllipticCurve.Point.MultivePoint;
import Encryption.ABE.ABEConfig;
import Encryption.ABE.utils.BooleanFormulaParser;
import utils.ElementCounter;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class PublicParam extends Encryption.ABE.MAABE.Components.PublicParam<
        AuthPublicKey, AuthSecretKey, Authority, User, Policy,
        Identity, PublicKeyGroup, SecretKeyGroup, PublicKey, SecretKey, PlainText, CipherText> {
    MultivePoint g, egg;


    private byte[] hash(String input) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return digest.digest(input.getBytes(StandardCharsets.UTF_8));
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    public final MultivePoint H(String m) {
        return curve.HashToG1(hash("H" + m));
    }

    public final MultivePoint F(String m) {
        return curve.HashToG1(hash("F" + m));
    }

    protected PublicParam(ABEConfig abeConfig) {
        super(abeConfig);
    }

    @Override
    public Policy createPolicy(String BooleanFormulas) {
        Policy res = new Policy();
        BooleanFormulaParser.parse(res.MSP, curve, BooleanFormulas);
        return res;
    }

    @Override
    public AuthPublicKey createAuthPublicKey() {
        return new AuthPublicKey();
    }

    @Override
    public AuthSecretKey createAuthSecretKey() {
        return new AuthSecretKey();
    }

    @Override
    public User createUser(String ID) {
        User res = new User(createIdentity(ID));
        res.pkg = createPublicKeyGroup();
        res.skg = createSecretKeyGroup();
        return res;
    }

    @Override
    public Identity createIdentity(String ID) {
        return new Identity(ID);
    }

    @Override
    public PublicKey createPublicKey() {
        return new PublicKey();
    }

    @Override
    public PublicKeyGroup createPublicKeyGroup() {
        return new PublicKeyGroup();
    }

    @Override
    public SecretKey createSecretKey() {
        return new SecretKey();
    }

    @Override
    public SecretKeyGroup createSecretKeyGroup() {
        return new SecretKeyGroup();
    }

    @Override
    public Authority createAuthority() {
        Authority res = new Authority();
        res.apk = createAuthPublicKey();
        res.ask = createAuthSecretKey();
        return res;
    }

    @Override
    public PlainText createPlainText(String msg) {
        PlainText res = new PlainText();
        res.m = curve.HashToGT(hash(msg));
        return res;
    }

    @Override
    public CipherText createCipherText() {
        return new CipherText();
    }

    @Override
    public final ElementCounter TheoSize() {
        ElementCounter res = new ElementCounter();
        res.count(this);
        return res;
    }
}
