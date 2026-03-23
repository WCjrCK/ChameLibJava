package ChameleonHash.PBCH.MAPBCH.Components;

import utils.ElementCounter;

public abstract class User<
        PP extends PublicParam,
        AUTH extends Authority,
        A extends Attribute,
        P extends Policy,
        M extends Message,
        H extends HashValue<H>,
        R extends Randomness> {
    public abstract void AddAttr(A attr);

    public abstract void Setup(PP pp);

    public abstract void KeyGen(PP pp, AUTH auth);

    public abstract void Hash(H h, R r, PP pp, P P, M m);

    public abstract boolean Verify(PP pp, M m, H h, R r);

    public abstract void Collision(R r_p, PP pp, M m, H h, R r, M m_p);

    public abstract ElementCounter TheoSize();
}
