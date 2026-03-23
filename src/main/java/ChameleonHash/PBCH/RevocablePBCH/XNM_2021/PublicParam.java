package ChameleonHash.PBCH.RevocablePBCH.XNM_2021;

import ChameleonHash.CH.CHConfig;
import ChameleonHash.CH.CHET.CHETFactory;
import ChameleonHash.Interface.CHET;
import ChameleonHash.PBCH.PBCHConfig;
import EllipticCurve.Point.Scalar;
import Encryption.ABE.ABEConfig;
import Encryption.ABE.ABEName;
import Encryption.ABE.RevocableABE.XNM_2021.Core;
import Encryption.SE.SE;
import Encryption.SE.SEConfig;
import Encryption.SE.SEFactory;
import utils.ElementCounter;
import utils.Serializer;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Objects;
import java.util.Random;

public class PublicParam
        extends ChameleonHash.PBCH.RevocablePBCH.Components.PublicParam<
        MasterPublicKey, MasterSecretKey, State, Revocated, UpdateKey,
        SecretKey, DecryptKey, Authority, User, Identity, Attributes, Info, Policy, Message, HashValue, Randomness>
{
    protected Core RABE = new Core();
    protected Encryption.ABE.RevocableABE.XNM_2021.PublicParam RABE_pp;
    protected CHET CHET;
    protected ChameleonHash.CH.CHET.Components.PublicParam CHET_pp;
    protected SE SE;
    protected Encryption.SE.Components.PublicParam SE_pp;
    Random rand = new Random();

    public final Scalar H(String m) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(m.getBytes(StandardCharsets.UTF_8));
            return curve.HashToZp(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    protected PublicParam(PBCHConfig config) {
        super(config.curveConfig);
        RABE_pp = RABE.createPublicParam(new ABEConfig(ABEName.RABE_XNM_2021, config.curveConfig, config.params));
        CHConfig CHETConfig = (CHConfig) Objects.requireNonNull(config.params.get("chet_config"), "未设置黑盒CHET方案（chet_config）");
        CHET = CHETFactory.createScheme(CHETConfig);
        CHET_pp = CHET.createPublicParam(CHETConfig);
        SEConfig SEConfig = (SEConfig) Objects.requireNonNull(config.params.get("se_config"), "未设置黑盒对称加密方案（se_config）");
        SE = SEFactory.createSE(SEConfig);
        SE_pp = SE.createPublicParam(SEConfig);
    }

    @Override
    public MasterPublicKey createMasterPublicKey() {
        MasterPublicKey res = new MasterPublicKey();
        res.CHET_pk = CHET_pp.createPublicKey();
        res.RABE_mpk = RABE_pp.createMasterPublicKey();
        return res;
    }

    @Override
    public MasterSecretKey createMasterSecretKey() {
        MasterSecretKey res = new MasterSecretKey();
        res.CHET_sk = CHET_pp.createSecretKey();
        res.RABE_msk = RABE_pp.createMasterSecretKey();
        return res;
    }

    @Override
    public State createState() {
        State res = new State();
        res.RABE_st = RABE_pp.createState();
        return res;
    }

    @Override
    public Revocated createRevocated() {
        return new Revocated();
    }

    @Override
    public UpdateKey createUpdateKey() {
        return new UpdateKey();
    }

    @Override
    public DecryptKey createDecryptKey() {
        return new DecryptKey();
    }

    @Override
    public Info createInfo() {
        Info res = new Info();
        res.RABE_info = RABE_pp.createInfo();
        return res;
    }

    @Override
    public Message createMessage(String msg) {
        Message res = new Message();
        res.CHET_m = CHET_pp.createMessage(msg);
        return res;
    }

    @Override
    public Authority createAuthority() {
        Authority res = new Authority();
        res.msk = createMasterSecretKey();
        res.st = createState();
        return res;
    }

    @Override
    public User createUser(String ID) {
        User res = new User();
        res.RABE_user = RABE_pp.createUser(ID);
        res.id = new Identity();
        res.id.RABE_id = res.RABE_user.id;
        res.S = createAttributes();
        res.sk = createSecretKey();
        return res;
    }

    @Override
    public Identity createIdentity(String ID) {
        Identity res = new Identity();
        res.RABE_id = RABE_pp.createIdentity(ID);
        return res;
    }

    @Override
    public SecretKey createSecretKey() {
        SecretKey res = new SecretKey();
        res.CHET_sk = CHET_pp.createSecretKey();
        res.RABE_sk = RABE_pp.createSecretKey();
        return res;
    }

    @Override
    public Policy createPolicy(String BooleanFormula) {
        Policy res = new Policy();
        res.RABE_P = RABE_pp.createPolicy(BooleanFormula);
        return res;
    }

    @Override
    public Attributes createAttributes() {
        return new Attributes();
    }

    @Override
    public HashValue createHashValue() {
        HashValue res = new HashValue();
        res.SE_ct = SE_pp.createCipherText();
        res.CHET_h = CHET_pp.createHashValue();
        res.RABE_ct = RABE_pp.createCipherText();
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

    public byte[] serializeInfo(Info target) {
        Objects.requireNonNull(target, "Info 不能为空");
        return Serializer.pack(RABE_pp.serializeInfo(target.RABE_info));
    }

    public void deserializeInfo(Info target, byte[] data) {
        Objects.requireNonNull(target, "Info 不能为空");
        Serializer.Reader reader = new Serializer.Reader(data);
        RABE_pp.deserializeInfo(target.RABE_info, reader.readBytes());
        reader.ensureFullyConsumed();
    }

    @Override
    public final ElementCounter TheoSize() {
        ElementCounter res = new ElementCounter();
        res.count(this);
        return res;
    }
}
