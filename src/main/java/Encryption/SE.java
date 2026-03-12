package Encryption;

import Encryption.Components.CipherText;
import Encryption.Components.PlainText;
import Encryption.Components.PublicParam;
import Encryption.Components.SecretKey;

import java.util.Map;

public abstract class SE {
    public abstract void Encrypt(CipherText ct, PublicParam pp, SecretKey sk, PlainText pt);

    public abstract void Decrypt(PlainText pt, PublicParam pp, SecretKey sk, CipherText ct);

    public abstract PublicParam createPublicParam(Map<String, Object> params);

    public abstract SecretKey createSecretKey();

    public abstract PlainText createPlainText(String m);

    public abstract CipherText createCipherText();
}
