package Encryption.PKE.Components;

import utils.ElementCounter;

public abstract class PublicParam<
        PK extends PublicKey,
        SK extends SecretKey,
        PT extends PlainText<PT>,
        CT extends CipherText<CT>
        > {
    public abstract PK createPublicKey();

    public byte[] serializePublicKey(PK target) {
        throw new UnsupportedOperationException("当前方案未实现 PublicKey 序列化");
    }

    public void deserializePublicKey(PK target, byte[] data) {
        throw new UnsupportedOperationException("当前方案未实现 PublicKey 反序列化");
    }

    public byte[] serializeSecretKey(SK target) {
        throw new UnsupportedOperationException("当前方案未实现 SecretKey 序列化");
    }

    public void deserializeSecretKey(SK target, byte[] data) {
        throw new UnsupportedOperationException("当前方案未实现 SecretKey 反序列化");
    }

    public byte[] serializeCipherText(CT target) {
        throw new UnsupportedOperationException("当前方案未实现 CipherText 序列化");
    }

    public void deserializeCipherText(CT target, byte[] data) {
        throw new UnsupportedOperationException("当前方案未实现 CipherText 反序列化");
    }

    public abstract SK createSecretKey();

    public abstract SK createSecretKey(byte[] sk);

    public abstract PT createPlainText(String m);

    public abstract PT createPlainText(byte[] m);

    public abstract CT createCipherText();

    public abstract ElementCounter TheoSize();
}
