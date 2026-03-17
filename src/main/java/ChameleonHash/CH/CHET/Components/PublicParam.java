package ChameleonHash.CH.CHET.Components;

import ChameleonHash.CH.Components.*;
import EllipticCurve.Curve.Config;

public abstract class PublicParam<
        PK extends PublicKey,
        SK extends SecretKey,
        M extends Message,
        E extends ETrapdoor,
        H extends HashValue<H>,
        R extends Randomness
        > extends ChameleonHash.CH.Components.PublicParam<PK, SK, M, H, R> {
    protected PublicParam(Config config) {
        super(config);
    }

    public abstract E createETrapdoor();

    public byte[] serializeETrapdoor(E target) {
        throw new UnsupportedOperationException("当前方案未实现 ETrapdoor 序列化");
    }

    public void deserializeETrapdoor(E target, byte[] data) {
        throw new UnsupportedOperationException("当前方案未实现 ETrapdoor 反序列化");
    }
}
