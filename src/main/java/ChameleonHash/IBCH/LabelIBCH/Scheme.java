package ChameleonHash.IBCH.LabelIBCH;

import ChameleonHash.Config;
import ChameleonHash.IBCH.Components.*;
import ChameleonHash.IBCH.IBCH;
import ChameleonHash.Interface.LabelIBCH;

public abstract class Scheme<
        PP extends ChameleonHash.IBCH.LabelIBCH.Components.PublicParam<MSK, SK, ID, M, L, H, R>,
        MSK extends MasterSecretKey,
        SK extends SecretKey,
        ID extends Identity,
        M extends Message,
        L extends ChameleonHash.IBCH.LabelIBCH.Components.Label,
        H extends HashValue<H>,
        R extends Randomness
        > extends IBCH<PP, MSK, SK, ID, M, H, R> implements LabelIBCH<PP, MSK, SK, ID, M, L, H, R> {
    public abstract PP createPublicParam(Config config);

    public final void Hash(H h, R r, PP pp, ID ID, M m) {
        throw new RuntimeException("该方案包含 Label 组件");
    }

    public final boolean Verify(PP pp, ID ID, M m, H h, R r) {
        throw new RuntimeException("该方案包含 Label 组件");
    }

    public final void Collision(R r_p, PP pp, ID ID, SK sk, M m, H h, R r, M m_p) {
        throw new RuntimeException("该方案包含 Label 组件");
    }

    public abstract void Hash(H h, R r, PP pp, ID ID, M m, L l);

    public abstract boolean Verify(PP pp, ID ID, M m, L l, H h, R r);

    public abstract void Collision(R r_p, PP pp, ID ID, SK sk, M m, L l, H h, R r, M m_p);
}
