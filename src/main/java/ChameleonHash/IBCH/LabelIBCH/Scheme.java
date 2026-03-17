package ChameleonHash.IBCH.LabelIBCH;

import ChameleonHash.IBCH.Components.*;
import ChameleonHash.IBCH.IBCH;
import ChameleonHash.IBCH.IBCHConfig;
import ChameleonHash.Interface.LabelIBCH;

public abstract class Scheme<
        PP extends ChameleonHash.IBCH.LabelIBCH.Components.PublicParam<MSK, SK, M, ID, L, H, R>,
        MSK extends MasterSecretKey,
        SK extends SecretKey,
        ID extends Identity,
        M extends Message,
        L extends ChameleonHash.IBCH.LabelIBCH.Components.Label,
        H extends HashValue<H>,
        R extends Randomness
        > extends IBCH implements LabelIBCH<PP, MSK, SK, ID, M, L, H, R> {
    public abstract PP createPublicParam(IBCHConfig config);

    public abstract void Setup(PP pp, MSK msk);

    public abstract void KeyGen(SK sk, PP pp, MSK msk, ID ID);

    public abstract void Hash(H h, R r, PP pp, ID ID, M m, L l);

    public abstract boolean Verify(PP pp, ID ID, M m, L l, H h, R r);

    public abstract void Collision(R r_p, PP pp, ID ID, SK sk, M m, L l, H h, R r, M m_p);
}
