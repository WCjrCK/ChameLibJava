package ChameleonHash.PBCH.MAPBCH.Components;

import utils.ElementCounter;

public abstract class Authority<
        PP extends PublicParam,
        PK extends PublicKey,
        SK extends SecretKey,
        ID extends Identity,
        A extends Attribute
        > {
    public abstract void AddAttr(A attr);

    public abstract void Setup(PP pp);

    public abstract void KeyGen(PK pk, SK sk, PP pp, ID id, A attr);

    public abstract ElementCounter TheoSize();
}
