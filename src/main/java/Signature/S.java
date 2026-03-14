package Signature;

import Signature.Components.*;

public abstract class S<
        PP extends PublicParam,
        PK extends PublicKey,
        SK extends SecretKey,
        M extends Message,
        S extends SignValue
        > {
    public abstract PP createPublicParam(Config config);

    public abstract void Setup(PP pp);

    public abstract void KeyGen(PK pk, SK sk, PP pp);

    public abstract void Sign(S s, PP pp, SK sk, M m);

    public abstract boolean Verify(PP pp, PK pk, S s, M m);
}
