package ChameleonHash.PBCH.RevocablePBCH.Components;

import utils.ElementCounter;

public abstract class User<
        PP extends PublicParam,
        MPK extends MasterPublicKey,
        PK extends PublicKey,
        SK extends SecretKey,
        DK extends DecryptKey,
        ID extends Identity,
        A extends Attributes,
        I extends Info,
        P extends Policy,
        M extends Message,
        H extends HashValue<H>,
        R extends Randomness> {
    public A S;
    public SK sk;
    public DK dk;
    public final ID id;

    protected User(ID id) {
        this.id = id;
    }

    public abstract void Hash(H h, R r, PP pp, MPK mpk, ID id, PK pk, M m, P P, I info);

    public abstract boolean Verify(PP pp, MPK mpk, PK pk, M m, H h, R r);

    public abstract void Collision(R r_p, PP pp, MPK mpk, PK pk, M m, P P, H h, R r, M m_p);

    public abstract ElementCounter TheoSize();
}
