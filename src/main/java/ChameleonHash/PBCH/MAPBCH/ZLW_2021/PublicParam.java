package ChameleonHash.PBCH.MAPBCH.ZLW_2021;

import ChameleonHash.CH.CHConfig;
import ChameleonHash.CH.CHET.CHETFactory;
import ChameleonHash.Interface.CHET;
import ChameleonHash.PBCH.PBCHConfig;
import Encryption.ABE.ABEConfig;
import Encryption.ABE.Interface.MAABE;
import Encryption.ABE.MAABE.MAABEFactory;
import utils.ElementCounter;

import java.util.Objects;

public class PublicParam extends ChameleonHash.PBCH.MAPBCH.Components.PublicParam<
        PublicKey, SecretKey, Authority, User, Identity, Attribute, Policy,
        Message, HashValue, Randomness> {
    protected CHET CHET;
    protected ChameleonHash.CH.CHET.Components.PublicParam CHET_pp;
    protected MAABE MAABE;
    protected Encryption.ABE.MAABE.Components.PublicParam MAABE_pp;
    protected ChameleonHash.CH.CHET.Components.PublicKey CHET_pk;
    protected ChameleonHash.CH.CHET.Components.SecretKey CHET_sk;

    protected PublicParam(PBCHConfig config) {
        super(config.curveConfig);

        CHConfig chetConfig = (CHConfig) Objects.requireNonNull(config.params.get("chet_config"), "未设置黑盒 CHET 方案（chet_config）");
        CHET = CHETFactory.createScheme(chetConfig);
        CHET_pp = CHET.createPublicParam(chetConfig);
        CHET_pk = CHET_pp.createPublicKey();
        CHET_sk = CHET_pp.createSecretKey();

        ABEConfig maabeConfig = (ABEConfig) Objects.requireNonNull(config.params.get("maabe_config"), "未设置黑盒 MA-ABE 方案（maabe_config）");
        MAABE = MAABEFactory.createMAABE(maabeConfig);
        MAABE_pp = MAABE.createPublicParam(maabeConfig);
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
        User res = new User();
        res.MAABE_user = MAABE_pp.createUser(ID);
        return res;
    }

    @Override
    public Identity createIdentity(String ID) {
        return new Identity(MAABE_pp.createIdentity(ID));
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
