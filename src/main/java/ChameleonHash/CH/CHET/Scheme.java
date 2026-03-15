package ChameleonHash.CH.CHET;

import ChameleonHash.CH.CH;
import ChameleonHash.CH.CHET.Comoponents.ETrapdoor;
import ChameleonHash.CH.Components.*;
import ChameleonHash.CH.LabelCH.Components.Label;
import ChameleonHash.Interface.CHET;

public abstract class Scheme<
        PP extends PublicParam<PK, SK, M, H, R>,
        PK extends PublicKey,
        SK extends SecretKey,
        M extends Message,
        ET extends ETrapdoor,
        H extends HashValue<H>,
        R extends Randomness
        >
        extends CH<PP, PK, SK, M, Label, ET, H, R> implements CHET<PP, PK, SK, M, ET, H, R> {
    public final void Hash(H h, R r, PP pp, PK pk, M m, Label l) {
        throw new RuntimeException("该方案不包含 Label 组件");
    }

    public final boolean Verify(PP pp, PK pk, M m, Label l, H h, R r) {
        throw new RuntimeException("该方案不包含 Label 组件");
    }

    public final void Collision(R r_p, PP pp, PK pk, SK sk, M m, Label l, H h, R r, M m_p) {
        throw new RuntimeException("该方案不包含 Label 组件");
    }
}
