package ChameleonHash.PBCH.BasePBCH.DSS_2019;

import ChameleonHash.CH.CHConfig;
import ChameleonHash.CH.CHET.CHETFactory;
import ChameleonHash.Interface.CHET;
import ChameleonHash.PBCH.PBCHConfig;
import EllipticCurve.Point.Scalar;
import Encryption.ABE.ABEConfig;
import Encryption.ABE.ABEName;
import Encryption.ABE.BaseABE.FAME.FAMECore;
import Encryption.SE.SE;
import Encryption.SE.SEConfig;
import Encryption.SE.SEFactory;
import utils.ElementCounter;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Objects;
import java.util.Random;

public class PublicParam
        extends ChameleonHash.PBCH.Components.PublicParam<MasterPublicKey, MasterSecretKey, SecretKey, Policy, Attributes, Message, HashValue, Randomness> {
    protected CHET CHETScheme;
    protected ChameleonHash.CH.CHET.Components.PublicParam CHET_pp;
    protected FAMECore FAME = new FAMECore();
    protected Encryption.ABE.BaseABE.FAME.PublicParam FAME_pp;
    protected SE SEScheme;
    protected Encryption.SE.Components.PublicParam SE_pp;
    protected Random rand = new Random();

    protected PublicParam(PBCHConfig config) {
        super(config.curveConfig);
        CHConfig chetConfig = (CHConfig) Objects.requireNonNull(config.params.get("chet_config"), "未设置方案的黑盒临时陷门变色龙哈希方案（chet_config）");
        CHETScheme = CHETFactory.createScheme(chetConfig);
        CHET_pp = CHETScheme.createPublicParam(chetConfig);
        ABEConfig FAMEConfig = new ABEConfig(ABEName.ABE_FAME, config.curveConfig);
        FAME_pp = FAME.createPublicParam(FAMEConfig);
        SEConfig seConfig = (SEConfig) Objects.requireNonNull(config.params.get("se_config"), "未设置方案的黑盒对称加密方案（se_config）");
        SEScheme = SEFactory.createSE(seConfig);
        SE_pp = SEScheme.createPublicParam(seConfig);
    }

    protected Scalar H(String m) {
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
        res.CHET_m = CHET_pp.createMessage(msg);
        return res;
    }

    @Override
    public MasterPublicKey createMasterPublicKey() {
        MasterPublicKey res = new MasterPublicKey();
        res.CHET_pk = CHET_pp.createPublicKey();
        res.FAME_mpk = FAME_pp.createMasterPublicKey();
        return res;
    }

    @Override
    public MasterSecretKey createMasterSecretKey() {
        MasterSecretKey res = new MasterSecretKey();
        res.CHET_sk = CHET_pp.createSecretKey();
        res.FAME_msk = FAME_pp.createMasterSecretKey();
        return res;
    }

    @Override
    public SecretKey createSecretKey() {
        SecretKey res = new SecretKey();
        res.CHET_sk = CHET_pp.createSecretKey();
        res.FAME_sk = FAME_pp.createSecretKey();
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
        HashValue res = new HashValue();
        res.CHET_h = CHET_pp.createHashValue();
        res.FAME_ct = FAME_pp.createCipherText();
        res.SE_ct = SE_pp.createCipherText();
        return res;
    }

    @Override
    public Randomness createRandomness() {
        Randomness res = new Randomness();
        res.CHET_r = CHET_pp.createRandomness();
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
}
