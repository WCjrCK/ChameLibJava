package Encryption.ABE.RevocableABE.TMM_2022;

import EllipticCurve.Point.MultivePoint;
import Encryption.ABE.ABEConfig;
import Encryption.ABE.BaseABE.FAME.FAMECore;
import utils.ElementCounter;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Objects;

public class PublicParam
        extends Encryption.ABE.RevocableABE.Components.PublicParam<
        MasterPublicKey, MasterSecretKey, State, Revocated, Authority, User, Identity,
        Info, UpdateKey, SecretKey, DecryptKey, PlainText, CipherText> {
    protected FAMECore FAME = new FAMECore();
    protected Encryption.ABE.BaseABE.FAME.PublicParam FAME_pp;
    protected int MAX_USER;

    protected PublicParam(ABEConfig abeConfig) {
        super(abeConfig);
        MAX_USER = (int) Objects.requireNonNull(abeConfig.params.get("max_user"), "未设置方案最大用户数（max_user）");
        FAME_pp = FAME.createPublicParam(abeConfig);
    }

    @Override
    public Authority createAuthority() {
        Authority res = new Authority();
        res.msk = createMasterSecretKey();
        res.st = createState();
        res.rl = createRevocated();
        res.uk = createKeyUpdater();
        return res;
    }

    public final MultivePoint H(String m) {
        return FAME_pp.H(m);
    }

    @Override
    public State createState() {
        return new State(MAX_USER);
    }

    @Override
    public Revocated createRevocated() {
        return new Revocated();
    }

    @Override
    public User createUser(String ID) {
        User res = new User(createIdentity(ID));
        res.sk = createSecretKey();
        res.dk = createDecryptKey();
        res.S = createAttributes();
        return res;
    }

    @Override
    public Identity createIdentity(String ID) {
        MessageDigest messageDigest;
        byte[] hash;
        try {
            messageDigest = MessageDigest.getInstance("SHA-256");
            messageDigest.update(ID.getBytes(StandardCharsets.UTF_8));
            hash = messageDigest.digest();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
        Identity res = new Identity();
        res.id = curve.HashToG1(hash);
        return res;
    }

    @Override
    public Info createInfo() {
        return new Info();
    }

    @Override
    public UpdateKey createKeyUpdater() {
        return new UpdateKey();
    }

    @Override
    public DecryptKey createDecryptKey() {
        DecryptKey res = new DecryptKey();
        res.FAME_sk = FAME_pp.createSecretKey();
        return res;
    }

    @Override
    public Policy createPolicy(String BooleanFormulas) {
        Policy res = new Policy();
        res.FAME_p = FAME_pp.createPolicy(BooleanFormulas);
        return res;
    }

    @Override
    public MasterPublicKey createMasterPublicKey() {
        MasterPublicKey res = new MasterPublicKey();
        res.FAME_mpk = FAME_pp.createMasterPublicKey();
        return res;
    }

    @Override
    public MasterSecretKey createMasterSecretKey() {
        MasterSecretKey res = new MasterSecretKey();
        res.FAME_msk = FAME_pp.createMasterSecretKey();
        return res;
    }

    @Override
    public SecretKey createSecretKey() {
        SecretKey res = new SecretKey();
        res.FAME_sk = FAME_pp.createSecretKey();
        return res;
    }

    @Override
    public PlainText createPlainText(String msg) {
        MessageDigest messageDigest;
        byte[] hash;
        try {
            messageDigest = MessageDigest.getInstance("SHA-256");
            messageDigest.update(msg.getBytes(StandardCharsets.UTF_8));
            hash = messageDigest.digest();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
        PlainText res = new PlainText();
        res.m = curve.HashToZp(hash);
        return res;
    }

    @Override
    public CipherText createCipherText() {
        CipherText res = new CipherText();
        res.FAME_ct = FAME_pp.createCipherText();
        return res;
    }

    @Override
    public final ElementCounter TheoSize() {
        ElementCounter res = new ElementCounter();
        res.count(this);
        return res;
    }
}
