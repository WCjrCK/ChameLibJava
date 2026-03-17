package ChameleonHash.CH.CHET.BC_CDK_2017;

import ChameleonHash.CH.BaseCH.BaseCHFactory;
import ChameleonHash.CH.CHConfig;
import ChameleonHash.Interface.BaseCH;
import utils.ElementCounter;
import utils.Serializer;

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
    public byte[] serializePublicKey(PublicKey target) {
        Objects.requireNonNull(target, "PublicKey 不能为空");
        return Serializer.pack(ch_pp.serializePublicKey(target.ch_pk));
    }

    @Override
    public void deserializePublicKey(PublicKey target, byte[] data) {
        Objects.requireNonNull(target, "PublicKey 不能为空");
        Serializer.Reader reader = new Serializer.Reader(data);
        target.ch_pk = ch_pp.createPublicKey();
        ch_pp.deserializePublicKey(target.ch_pk, reader.readBytes());
        reader.ensureFullyConsumed();
    }

    @Override
    public byte[] serializeSecretKey(SecretKey target) {
        Objects.requireNonNull(target, "SecretKey 不能为空");
        return Serializer.pack(ch_pp.serializeSecretKey(target.ch_sk));
    }

    @Override
    public void deserializeSecretKey(SecretKey target, byte[] data) {
        Objects.requireNonNull(target, "SecretKey 不能为空");
        Serializer.Reader reader = new Serializer.Reader(data);
        target.ch_sk = ch_pp.createSecretKey();
        ch_pp.deserializeSecretKey(target.ch_sk, reader.readBytes());
        reader.ensureFullyConsumed();
    }

    @Override
    public byte[] serializeMessage(Message target) {
        Objects.requireNonNull(target, "Message 不能为空");
        return Serializer.pack(ch_pp.serializeMessage(target.m));
    }

    @Override
    public void deserializeMessage(Message target, byte[] data) {
        Objects.requireNonNull(target, "Message 不能为空");
        Serializer.Reader reader = new Serializer.Reader(data);
        target.m = ch_pp.createMessage("");
        ch_pp.deserializeMessage(target.m, reader.readBytes());
        reader.ensureFullyConsumed();
    }

    @Override
    public byte[] serializeHashValue(HashValue target) {
        Objects.requireNonNull(target, "HashValue 不能为空");
        return Serializer.pack(
                ch_pp.serializePublicKey(target.ch_pk),
                ch_pp.serializeHashValue(target.h_1),
                ch_pp.serializeHashValue(target.h_2)
        );
    }

    @Override
    public void deserializeHashValue(HashValue target, byte[] data) {
        Objects.requireNonNull(target, "HashValue 不能为空");
        Serializer.Reader reader = new Serializer.Reader(data);
        target.ch_pk = ch_pp.createPublicKey();
        ch_pp.deserializePublicKey(target.ch_pk, reader.readBytes());
        target.h_1 = ch_pp.createHashValue();
        ch_pp.deserializeHashValue(target.h_1, reader.readBytes());
        target.h_2 = ch_pp.createHashValue();
        ch_pp.deserializeHashValue(target.h_2, reader.readBytes());
        reader.ensureFullyConsumed();
    }

    @Override
    public byte[] serializeRandomness(Randomness target) {
        Objects.requireNonNull(target, "Randomness 不能为空");
        return Serializer.pack(
                ch_pp.serializeRandomness(target.r_1),
                ch_pp.serializeRandomness(target.r_2)
        );
    }

    @Override
    public void deserializeRandomness(Randomness target, byte[] data) {
        Objects.requireNonNull(target, "Randomness 不能为空");
        Serializer.Reader reader = new Serializer.Reader(data);
        target.r_1 = ch_pp.createRandomness();
        ch_pp.deserializeRandomness(target.r_1, reader.readBytes());
        target.r_2 = ch_pp.createRandomness();
        ch_pp.deserializeRandomness(target.r_2, reader.readBytes());
        reader.ensureFullyConsumed();
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

    @Override
    public byte[] serializeETrapdoor(ETrapdoor target) {
        Objects.requireNonNull(target, "ETrapdoor 不能为空");
        return Serializer.pack(ch_pp.serializeSecretKey(target.ch_sk));
    }

    @Override
    public void deserializeETrapdoor(ETrapdoor target, byte[] data) {
        Objects.requireNonNull(target, "ETrapdoor 不能为空");
        Serializer.Reader reader = new Serializer.Reader(data);
        target.ch_sk = ch_pp.createSecretKey();
        ch_pp.deserializeSecretKey(target.ch_sk, reader.readBytes());
        reader.ensureFullyConsumed();
    }
}
