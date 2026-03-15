package ChameleonHash.IBCH;

import ChameleonHash.Config;
import ChameleonHash.IBCH.Components.*;
import ChameleonHash.IBCH.LabelIBCH.Components.Label;
import ChameleonHash.Scheme;

public abstract class IBCH<
        PP extends PublicParam<MSK, SK, M, ID, H, R>,
        MSK extends MasterSecretKey,
        SK extends SecretKey,
        ID extends Identity,
        M extends Message,
        L extends Label,
        H extends HashValue<H>,
        R extends Randomness
        > extends Scheme<PP, SK, M, H, R> {
    public abstract PP createPublicParam(Config config);

    public abstract void Setup(PP pp, MSK msk);

    public abstract void KeyGen(SK sk, PP pp, MSK msk, ID ID);

    public abstract void Hash(H h, R r, PP pp, ID ID, M m);

    public abstract void Hash(H h, R r, PP pp, ID ID, M m, L l);

    public abstract boolean Verify(PP pp, ID ID, M m, H h, R r);

    public abstract boolean Verify(PP pp, ID ID, M m, L l, H h, R r);

    public abstract void Collision(R r_p, PP pp, ID ID, SK sk, M m, H h, R r, M m_p);

    public abstract void Collision(R r_p, PP pp, ID ID, SK sk, M m, L l, H h, R r, M m_p);
}
