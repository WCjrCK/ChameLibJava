package ChameleonHash.PBCH.BAPBCH.TLL_2020;

import ChameleonHash.PBCH.PBCHConfig;
import EllipticCurve.Point.MultivePoint;
import EllipticCurve.Point.Scalar;
import Encryption.ABE.ABEConfig;
import Encryption.ABE.ABEName;
import Encryption.ABE.BaseABE.FAME.FAMECore;
import utils.ElementCounter;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Objects;
import java.util.Random;

public class PublicParam
        extends ChameleonHash.PBCH.BAPBCH.Components.PublicParam<
        MasterPublicKey, MasterSecretKey, SecretKey, Policy,
        Attributes, User, Message, HashValue, Randomness
        > {
    protected FAMECore FAME = new FAMECore();
    protected Encryption.ABE.BaseABE.FAME.PublicParam FAME_pp;
    protected Random rand = new Random();
    protected int ID_LEN;

    protected PublicParam(PBCHConfig config) {
        super(config.curveConfig);
        ABEConfig FAMEConfig = new ABEConfig(ABEName.ABE_FAME, config.curveConfig);
        FAME_pp = FAME.createPublicParam(FAMEConfig);
        ID_LEN = (int) Objects.requireNonNull(config.params.get("id_len"), "未设置身份标识长度（id_len）");
    }

    protected Scalar H2(String m) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(m.getBytes(StandardCharsets.UTF_8));
            return curve.HashToZp(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public Message createMessage(String msg) {
        Message res = new Message();
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(msg.getBytes(StandardCharsets.UTF_8));
            res.m = curve.HashToZp(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
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
        res.sk_0_g = new MultivePoint[3];
        return res;
    }

    @Override
    public Policy createPolicy(String BooleanFormula) {
        Policy res = new Policy();
        res.P = FAME_pp.createPolicy(BooleanFormula);
        return res;
    }

    @Override
    public Attributes createAttributes() {
        Attributes res = new Attributes();
        res.A = FAME_pp.createAttributes();
        return res;
    }

    @Override
    public HashValue createHashValue() {
        return new HashValue();
    }

    @Override
    public Randomness createRandomness() {
        Randomness res = new Randomness();
        res.FAME_ct = FAME_pp.createCipherText();
        return res;
    }

    @Override
    public String toString() {
        return "";
    }

    @Override
    public final ElementCounter TheoSize() {
        ElementCounter res = new ElementCounter();
        res.count(this);
        return res;
    }

    @Override
    public User createUser(int id_len) {
        User res = new User();
        res.sk = createSecretKey();
        res.S = createAttributes();
        res.ID = new Scalar[id_len];
        for (int i = 0;i < id_len;++i) res.ID[i] = curve.getRandomScalar();
        return res;
    }

    @Override
    public User createUser(User f, int id_len) {
        User res = new User();
        res.sk = createSecretKey();
        res.S = createAttributes();
        res.ID = new Scalar[id_len];
        System.arraycopy(f.ID, 0, res.ID, 0, f.ID.length);
        for (int i = f.ID.length;i < id_len;++i) res.ID[i] = curve.getRandomScalar();
        return res;
    }
}
