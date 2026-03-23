package ChameleonHash.PBCH.MAPBCH.MXN_2022;

import ChameleonHash.CH.CHConfig;
import ChameleonHash.CH.CHET.CHETFactory;
import ChameleonHash.Interface.CHET;
import ChameleonHash.PBCH.PBCHConfig;
import EllipticCurve.Point.Scalar;
import Encryption.ABE.ABEConfig;
import Encryption.ABE.ABEName;
import Encryption.ABE.MAABE.RW_2015.Core;
import Encryption.SE.SE;
import Encryption.SE.SEConfig;
import Encryption.SE.SEFactory;
import Signature.S;
import Signature.SConfig;
import Signature.SFactory;
import utils.ElementCounter;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Objects;

public class PublicParam extends ChameleonHash.PBCH.MAPBCH.Components.PublicParam<
        PublicKey, SecretKey, Authority, User, Identity, Attribute, Policy,
        Message, HashValue, Randomness> {
    protected Core MAABE = new Core();
    protected Encryption.ABE.MAABE.RW_2015.PublicParam MAABE_pp;

    protected CHET CHET;
    protected ChameleonHash.CH.CHET.Components.PublicParam CHET_pp;
    protected ChameleonHash.CH.CHET.Components.PublicKey CHET_pk;
    protected ChameleonHash.CH.CHET.Components.SecretKey CHET_sk;

    protected S DS;
    protected Signature.Components.PublicParam DS_pp;
    protected Signature.Components.PublicKey DS_pk;
    protected Signature.Components.SecretKey DS_sk;

    protected SE SE;
    protected Encryption.SE.Components.PublicParam SE_pp;

    protected PublicParam(PBCHConfig config) {
        super(config.curveConfig);

        MAABE_pp = MAABE.createPublicParam(new ABEConfig(ABEName.MAABE_RW_2015, config.curveConfig));

        CHConfig chetConfig = (CHConfig) Objects.requireNonNull(config.params.get("chet_config"), "未设置黑盒 CHET 方案（chet_config）");
        CHET = CHETFactory.createScheme(chetConfig);
        CHET_pp = CHET.createPublicParam(chetConfig);
        CHET_pk = CHET_pp.createPublicKey();
        CHET_sk = CHET_pp.createSecretKey();

        SConfig dsConfig = (SConfig) Objects.requireNonNull(config.params.get("ds_config"), "未设置黑盒签名方案（ds_config）");
        DS = SFactory.createS(dsConfig);
        DS_pp = DS.createPublicParam(dsConfig);
        DS_pk = DS_pp.createPublicKey();
        DS_sk = DS_pp.createSecretKey();

        SEConfig seConfig = (SEConfig) Objects.requireNonNull(config.params.get("se_config"), "未设置黑盒对称加密方案（se_config）");
        SE = SEFactory.createSE(seConfig);
        SE_pp = SE.createPublicParam(seConfig);
    }

    public final Scalar H(String m) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return curve.HashToZp(digest.digest(m.getBytes(StandardCharsets.UTF_8)));
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
    public Authority createAuthority() {
        Authority res = new Authority();
        res.MAABE_auth = MAABE_pp.createAuthority();
        return res;
    }

    @Override
    public User createUser(String ID) {
        User res = new User(ID);
        res.MAABE_user = MAABE_pp.createUser("0" + ID);
        res.DS_sigma_gid = DS_pp.createSignValue();
        return res;
    }

    @Override
    public Identity createIdentity(String ID) {
        return new Identity(ID, MAABE_pp.createIdentity("0" + ID));
    }

    public Attribute createAttribute(String attr) {
        Attribute res = new Attribute();
        res.MAABE_attr = MAABE_pp.createAttribute(attr);
        return res;
    }

    @Override
    public PublicKey createPublicKey() {
        PublicKey res = new PublicKey();
        res.MAABE_pk = MAABE_pp.createPublicKey();
        return res;
    }

    @Override
    public SecretKey createSecretKey() {
        SecretKey res = new SecretKey();
        res.MAABE_sk = MAABE_pp.createSecretKey();
        return res;
    }

    @Override
    public Policy createPolicy(String BooleanFormula) {
        Policy res = new Policy();
        res.MAABE_P = MAABE_pp.createPolicy(BooleanFormula);
        return res;
    }

    @Override
    public HashValue createHashValue() {
        HashValue res = new HashValue();
        res.CHET_h = CHET_pp.createHashValue();
        res.SE_ct = SE_pp.createCipherText();
        res.MAABE_ct = MAABE_pp.createCipherText();
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
    public ElementCounter TheoSize() {
        ElementCounter res = new ElementCounter();
        res.count(this);
        return res;
    }
}
