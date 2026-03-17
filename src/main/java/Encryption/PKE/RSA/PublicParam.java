package Encryption.PKE.RSA;

import utils.ElementCounter;
import utils.Serializer;

import java.util.Map;
import java.util.Objects;

public class PublicParam extends Encryption.PKE.Components.PublicParam<PublicKey, SecretKey, PlainText, CipherText> {
    int p_bit = 1024, q_bit = 1024, e_bit = -1;

    protected PublicParam(Map<String, Object> params) {
        super();
        if(params.containsKey("p_bit")) p_bit = (int) params.get("p_bit");
        if(params.containsKey("q_bit")) q_bit = (int) params.get("q_bit");
        if(params.containsKey("e_bit")) e_bit = (int) params.get("e_bit");
    }

    @Override
    public final PublicKey createPublicKey() {
        return new PublicKey();
    }
    @Override
    public final SecretKey createSecretKey() {
        return new SecretKey();
    }

    @Override
    public SecretKey createSecretKey(byte[] sk) {
        SecretKey res = new SecretKey();
        deserializeSecretKey(res, sk);
        return res;
    }

    @Override
    public final PlainText createPlainText(String m) {
        return new PlainText(m);
    }

    @Override
    public PlainText createPlainText(byte[] m) {
        return new PlainText(m);
    }

    @Override
    public final CipherText createCipherText() {
        return new CipherText();
    }

    @Override
    public byte[] serializePublicKey(PublicKey target) {
        Objects.requireNonNull(target, "PublicKey 不能为空");
        return Serializer.pack(
                Serializer.encodeBigInteger(target.N),
                Serializer.encodeBigInteger(target.e)
        );
    }

    @Override
    public void deserializePublicKey(PublicKey target, byte[] data) {
        Objects.requireNonNull(target, "PublicKey 不能为空");
        Serializer.Reader reader = new Serializer.Reader(data);
        target.N = reader.readBigInteger();
        target.e = reader.readBigInteger();
        reader.ensureFullyConsumed();
    }

    @Override
    public byte[] serializeSecretKey(SecretKey target) {
        Objects.requireNonNull(target, "SecretKey 不能为空");
        return Serializer.pack(
                Serializer.encodeBigInteger(target.p),
                Serializer.encodeBigInteger(target.q),
                Serializer.encodeBigInteger(target.d)
        );
    }

    @Override
    public void deserializeSecretKey(SecretKey target, byte[] data) {
        Objects.requireNonNull(target, "SecretKey 不能为空");
        Serializer.Reader reader = new Serializer.Reader(data);
        target.p = reader.readBigInteger();
        target.q = reader.readBigInteger();
        target.d = reader.readBigInteger();
        reader.ensureFullyConsumed();
    }

    @Override
    public byte[] serializeCipherText(CipherText target) {
        Objects.requireNonNull(target, "CipherText 不能为空");
        return Serializer.pack(Serializer.encodeBigInteger(target.ct));
    }

    @Override
    public void deserializeCipherText(CipherText target, byte[] data) {
        Objects.requireNonNull(target, "CipherText 不能为空");
        Serializer.Reader reader = new Serializer.Reader(data);
        target.ct = reader.readBigInteger();
        reader.ensureFullyConsumed();
    }

    @Override
    public final ElementCounter TheoSize() {
        ElementCounter res = new ElementCounter();
        res.count(this);
        return res;
    }
}
