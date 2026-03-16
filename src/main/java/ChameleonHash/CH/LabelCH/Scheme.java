package ChameleonHash.CH.LabelCH;

import ChameleonHash.CH.CH;
import ChameleonHash.CH.CHET.Components.ETrapdoor;
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
        >
        extends CH<PP, PK, SK, M, L, ETrapdoor, H, R> implements LabelCH<PP, PK, SK, M, L, H, R> {
    public final void Hash(H h, R r, PP pp, PK pk, M m) {
        throw new RuntimeException("该方案包含 Label 组件");
    }

    public final boolean Verify(PP pp, PK pk, M m, H h, R r) {
        throw new RuntimeException("该方案包含 Label 组件");
    }

    public final void Collision(R r_p, PP pp, PK pk, SK sk, M m, H h, R r, M m_p) {
        throw new RuntimeException("该方案包含 Label 组件");
    }

    public final void Hash(H h, R r, PP pp, PK pk, M m, ETrapdoor etd) {
        throw new RuntimeException("该方案不包含 ETrapdoor 组件");
    }

    public final void Collision(R r_p, PP pp, PK pk, SK sk, M m, ETrapdoor etd, H h, R r, M m_p) {
        throw new RuntimeException("该方案不包含 ETrapdoor 组件");
    }
}
