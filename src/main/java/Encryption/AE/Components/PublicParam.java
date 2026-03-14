package Encryption.AE.Components;

import Encryption.Components.CipherText;
import Encryption.Components.PlainText;
import Encryption.Components.SecretKey;

import java.util.Map;

public abstract class PublicParam<
        PK extends PublicKey,
        SK extends SecretKey,
        PT extends PlainText<PT>,
        CT extends CipherText<CT>
        > extends Encryption.Components.PublicParam<SK, PT, CT> {
    protected PublicParam(Map<String, Object> params) {
        super(params);
    }

    public abstract PK createPublicKey();

    public abstract SK createSecretKey();

    public abstract PT createPlainText(String m);

    public abstract CT createCipherText();
}
