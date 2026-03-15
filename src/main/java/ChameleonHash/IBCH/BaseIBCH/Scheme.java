package ChameleonHash.IBCH.BaseIBCH;

import ChameleonHash.Components.Label;
import ChameleonHash.IBCH.Components.*;
import ChameleonHash.IBCH.IBCH;
import ChameleonHash.Interface.BaseIBCH;

public abstract class Scheme<
        PP extends ChameleonHash.IBCH.Components.PublicParam<MSK, SK, ID, M, H, R>,
        MSK extends MasterSecretKey,
        SK extends SecretKey,
        ID extends Identity,
        M extends Message,
        H extends HashValue<H>,
        R extends Randomness
        > extends IBCH<PP, MSK, SK, ID, M, Label, H, R> implements BaseIBCH<PP, MSK, SK, ID, M, H, R> {
    @Override
    public final void Hash(H h, R r, PP pp, ID ID, M m, Label l) {
        throw new RuntimeException("该方案不包含 Label 组件");
    }

    @Override
    public final boolean Verify(PP pp, ID ID, M m, Label l, H h, R r) {
        throw new RuntimeException("该方案不包含 Label 组件");
    }

    @Override
    public final void Collision(R r_p, PP pp, ID ID, SK sk, M m, Label l, H h, R r, M m_p) {
        throw new RuntimeException("该方案不包含 Label 组件");
    }
}
