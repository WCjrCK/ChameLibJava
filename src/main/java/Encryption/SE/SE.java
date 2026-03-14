package Encryption.SE;

import Encryption.Components.CipherText;
import Encryption.Components.PlainText;
import Encryption.Components.PublicParam;
import Encryption.Components.SecretKey;

import java.util.Map;

public abstract class SE<
        PP extends PublicParam<SK, PT, CT>,
        SK extends SecretKey,
        PT extends PlainText<PT>,
        CT extends CipherText<CT>
        > {
    public abstract void KeyGen(SK sk, PP pp);

    public abstract void Encrypt(CT ct, PP pp, SK sk, PT pt);

    public abstract void Decrypt(PT pt, PP pp, SK sk, CT ct);

    public abstract PP createPublicParam(Map<String, Object> params);
}
