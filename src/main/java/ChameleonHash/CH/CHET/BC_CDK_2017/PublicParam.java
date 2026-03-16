package ChameleonHash.CH.CHET.BC_CDK_2017;

import ChameleonHash.CH.BaseCH.BaseCHFactory;
import ChameleonHash.CH.CHConfig;
import ChameleonHash.Interface.BaseCH;
import utils.ElementCounter;

import java.util.Objects;

public class PublicParam extends ChameleonHash.CH.CHET.Components.PublicParam<PublicKey, SecretKey, Message, ETrapdoor, HashValue, Randomness> {
    protected ChameleonHash.CH.Components.PublicParam ch_pp;
    protected BaseCH CHScheme;

    public PublicParam(CHConfig config) {
        super(config.curveConfig);
        CHConfig chConfig = (CHConfig) Objects.requireNonNull(config.params.get("ch_config"), "未设置方案的黑盒变色龙哈希方案（ch_config）");
        CHScheme = BaseCHFactory.createScheme(chConfig);
        ch_pp = CHScheme.createPublicParam(chConfig);
    }

    @Override
    public final Message createMessage(String msg) {
        Message res = new Message();
        res.m = ch_pp.createMessage(msg);
        return res;
    }

    @Override
    public final PublicKey createPublicKey() {
        PublicKey res =  new PublicKey();
        res.ch_pk = ch_pp.createPublicKey();
        return res;
    }

    @Override
    public final SecretKey createSecretKey() {
        SecretKey res = new SecretKey();
        res.ch_sk = ch_pp.createSecretKey();
        return res;
    }

    @Override
    public final HashValue createHashValue() {
        HashValue res = new HashValue();
        res.ch_pk = ch_pp.createPublicKey();
        res.h_1 = ch_pp.createHashValue();
        res.h_2 = ch_pp.createHashValue();
        return res;
    }

    @Override
    public final Randomness createRandomness() {
        Randomness res = new Randomness();
        res.r_1 = ch_pp.createRandomness();
        res.r_2 = ch_pp.createRandomness();
        return res;
    }

    @Override
    public final String toString() {
        return "";
    }

    @Override
    public final ElementCounter TheoSize() {
        ElementCounter res = new ElementCounter();
        res.count(this);
        return res;
    }

    @Override
    public ETrapdoor createETrapdoor() {
        ETrapdoor res = new ETrapdoor();
        res.ch_sk = ch_pp.createSecretKey();
        return res;
    }
}

