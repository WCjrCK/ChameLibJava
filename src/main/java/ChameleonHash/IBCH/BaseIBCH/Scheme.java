package ChameleonHash.IBCH.BaseIBCH;

import ChameleonHash.IBCH.Components.*;
import ChameleonHash.IBCH.IBCH;
import ChameleonHash.IBCH.IBCHConfig;
import ChameleonHash.Interface.BaseIBCH;

public abstract class Scheme<
        PP extends ChameleonHash.IBCH.Components.PublicParam<MSK, SK, M, ID, H, R>,
        MSK extends MasterSecretKey,
        SK extends SecretKey,
        ID extends Identity,
        M extends Message,
        H extends HashValue<H>,
        R extends Randomness
        > extends IBCH implements BaseIBCH<PP, MSK, SK, ID, M, H, R> {
    public abstract PP createPublicParam(IBCHConfig config);

    public abstract void Setup(PP pp, MSK msk);

    public abstract void KeyGen(SK sk, PP pp, MSK msk, ID ID);

    public abstract void Hash(H h, R r, PP pp, ID ID, M m);

    public abstract boolean Verify(PP pp, ID ID, M m, H h, R r);

    public abstract void Collision(R r_p, PP pp, ID ID, SK sk, M m, H h, R r, M m_p);
}
