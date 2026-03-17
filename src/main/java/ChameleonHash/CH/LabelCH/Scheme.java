package ChameleonHash.CH.LabelCH;

import ChameleonHash.CH.CH;
import ChameleonHash.CH.CHConfig;
import ChameleonHash.CH.Components.*;
import ChameleonHash.Interface.LabelCH;

public abstract class Scheme<
        PP extends ChameleonHash.CH.LabelCH.Components.PublicParam<PK, SK, M, L, H, R>,
        PK extends PublicKey,
        SK extends SecretKey,
        M extends Message,
        L extends ChameleonHash.CH.LabelCH.Components.Label,
        H extends HashValue<H>,
        R extends Randomness
        > extends CH implements LabelCH<PP, PK, SK, M, L, H, R> {
    public abstract PP createPublicParam(CHConfig config);

    public abstract void Setup(PP pp);

    public abstract void KeyGen(PK pk, SK sk, PP pp);

    public abstract void Hash(H h, R r, PP pp, PK pk, M m, L l);

    public abstract boolean Verify(PP pp, PK pk, M m, L l, H h, R r);

    public abstract void Collision(R r_p, PP pp, PK pk, SK sk, M m, L l, H h, R r, M m_p);
}
