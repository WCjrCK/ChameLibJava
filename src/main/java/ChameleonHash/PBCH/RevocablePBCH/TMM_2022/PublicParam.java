package ChameleonHash.PBCH.RevocablePBCH.TMM_2022;

import ChameleonHash.PBCH.PBCHConfig;
import EllipticCurve.Curve.CurveGroup;
import EllipticCurve.Point.MultivePoint;
import Encryption.ABE.ABEConfig;
import Encryption.ABE.ABEName;
import Encryption.ABE.RevocableABE.TMM_2022.Core;
import utils.ElementCounter;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Random;

public class PublicParam
        extends ChameleonHash.PBCH.RevocablePBCH.Components.PublicParam<
        MasterPublicKey, MasterSecretKey, State, PublicKey,
        SecretKey, Authority, User, Identity, Attributes, Info, Policy, Message, HashValue, Randomness>
{
    protected Core RABE = new Core();
    protected Encryption.ABE.RevocableABE.TMM_2022.PublicParam RABE_pp;
    protected CurveGroup curveGroup;
    Random rand = new Random();

    public final MultivePoint H(String m) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(m.getBytes(StandardCharsets.UTF_8));
            switch (curveGroup) {
                case G1:
                    return curve.HashToG1(hash);
                case G2:
                    return curve.HashToG2(hash);
                case GT:
                    return curve.HashToGT(hash);
                default:
                    throw new IllegalArgumentException("方案未适配指定群： " + curveGroup);
            }
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    protected PublicParam(PBCHConfig config) {
        super(config.curveConfig);
        if (!config.params.containsKey("curve_group")) throw new IllegalArgumentException("未设置方案所在群（curve_group）");
        curveGroup = (CurveGroup) config.params.get("curve_group");
        if (curveGroup == CurveGroup.Zp) throw new IllegalArgumentException("方案未适配指定群： " + curveGroup);
        RABE_pp = RABE.createPublicParam(new ABEConfig(ABEName.RABE_TMM_2022, config.curveConfig, config.params));
    }

    @Override
    public MasterPublicKey createMasterPublicKey() {
        MasterPublicKey res = new MasterPublicKey();
        res.RABE_mpk = RABE_pp.createMasterPublicKey();
        return res;
    }

    @Override
    public MasterSecretKey createMasterSecretKey() {
        MasterSecretKey res = new MasterSecretKey();
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
    public Info createInfo() {
        Info res = new Info();
        res.RABE_info = RABE_pp.createInfo();
        return res;
    }

    @Override
    public Message createMessage(String msg) {
        Message res = new Message();
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(msg.getBytes(StandardCharsets.UTF_8));
            res.m = curve.HashToZp(hash);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
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
        res.pk = createPublicKey();
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
    public PublicKey createPublicKey() {
        return new PublicKey();
    }

    @Override
    public SecretKey createSecretKey() {
        SecretKey res = new SecretKey();
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
        res.RABE_ct = RABE_pp.createCipherText();
        return res;
    }

    @Override
    public Randomness createRandomness() {
        return new Randomness();
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
