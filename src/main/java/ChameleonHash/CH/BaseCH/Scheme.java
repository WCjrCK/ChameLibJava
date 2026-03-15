package ChameleonHash.CH.BaseCH;

import ChameleonHash.CH.CH;
import ChameleonHash.CH.Components.*;
import ChameleonHash.Interface.BaseCH;

public abstract class Scheme<
        PP extends ChameleonHash.CH.Components.PublicParam<PK, SK, M, H, R>,
        PK extends PublicKey,
        SK extends SecretKey,
        M extends Message,
        H extends HashValue<H>,
        R extends Randomness
        >
        extends CH<PP, PK, SK, M, Label, H, R> implements BaseCH<PP, PK, SK, M, H, R> {
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
