package Encryption.ABE.MAABE.Components;

import utils.ElementCounter;

import java.util.HashSet;
import java.util.Set;

public abstract class Authority<
        PP extends PublicParam,
        APK extends AuthPublicKey,
        ASK extends AuthSecretKey,
        PK extends PublicKey,
        SK extends SecretKey,
        ID extends Identity,
        A extends Attribute
        > {
    public APK apk;
    public ASK ask;
    public Set<Attribute> controled_attr = new HashSet<>();

    public abstract void Setup(PP pp);

    public abstract void KeyGen(PK pk, SK sk, PP pp, ID id, A attr);

    public abstract ElementCounter TheoSize();
}
