package Encryption.PKE;


import Encryption.Components.CipherText;
import Encryption.Components.PlainText;
import Encryption.Components.SecretKey;
import Encryption.PKE.Components.PublicKey;
import Encryption.PKE.Components.PublicParam;

import java.util.Map;

public abstract class PKE<
        PP extends PublicParam<PK, SK, PT, CT>,
        PK extends PublicKey,
        SK extends SecretKey,
        PT extends PlainText<PT>,
        CT extends CipherText<CT>
        > {
    public abstract void Setup(PP pp);

    public abstract void KeyGen(PK pk, SK sk, PP pp);

    public abstract void Encrypt(CT ct, PP pp, PK pk, PT pt);

    public abstract void Decrypt(PT pt, PP pp, PK pk, SK sk, CT ct);

    public abstract PP createPublicParam(Map<String, Object> params);
}
