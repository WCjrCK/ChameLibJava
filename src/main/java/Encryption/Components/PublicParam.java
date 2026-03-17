package Encryption.Components;

import utils.ElementCounter;

public abstract class PublicParam<SK extends SecretKey, PT extends PlainText<PT>, CT extends CipherText<CT>> {
    protected PublicParam() {}

    public abstract SK createSecretKey();

    public abstract SK createSecretKey(byte[] sk);

    public abstract PT createPlainText(String m);

    public abstract PT createPlainText(byte[] m);

    public abstract CT createCipherText();

    public abstract ElementCounter TheoSize();
}
