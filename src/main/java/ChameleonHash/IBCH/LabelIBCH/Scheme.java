package ChameleonHash.IBCH.LabelIBCH;

import ChameleonHash.IBCH.Components.*;
import ChameleonHash.IBCH.IBCH;
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
        > extends IBCH<PP, MSK, SK, ID, M, L, H, R> implements LabelIBCH<PP, MSK, SK, ID, M, L, H, R> {
    @Override
    public final void Hash(H h, R r, PP pp, ID ID, M m) {
        throw new RuntimeException("该方案包含 Label 组件");
    }

    @Override
    public final boolean Verify(PP pp, ID ID, M m, H h, R r) {
        throw new RuntimeException("该方案包含 Label 组件");
    }

    @Override
    public final void Collision(R r_p, PP pp, ID ID, SK sk, M m, H h, R r, M m_p) {
        throw new RuntimeException("该方案包含 Label 组件");
    }
}
