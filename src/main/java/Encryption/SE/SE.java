package Encryption.SE;

import Encryption.SE.Components.CipherText;
import Encryption.SE.Components.PlainText;
import Encryption.SE.Components.PublicParam;
import Encryption.SE.Components.SecretKey;

public abstract class SE<
        PP extends PublicParam<SK, PT, CT>,
        SK extends SecretKey,
        PT extends PlainText<PT>,
        CT extends CipherText<CT>
        > {
    public abstract void Setup(PP pp);

    public abstract void KeyGen(SK sk, PP pp);

    public abstract void Encrypt(CT ct, PP pp, SK sk, PT pt);

    public abstract void Decrypt(PT pt, PP pp, SK sk, CT ct);

    public abstract PP createPublicParam(SEConfig seConfig);
}
