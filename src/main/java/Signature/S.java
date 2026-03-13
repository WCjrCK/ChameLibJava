package Signature;

import Signature.Components.*;

public abstract class S {
    public abstract PublicParam createPublicParam(Config config);

    public abstract void Setup(PublicParam pp);

    public abstract void KeyGen(PublicKey pk, SecretKey sk, PublicParam pp);

    public abstract void Sign(SignValue s, PublicParam pp, SecretKey sk, Message m);

    public abstract boolean Verify(PublicParam pp, PublicKey pk, SignValue s, Message m);
}
