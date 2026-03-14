package ChameleonHash.IBCH.Components;

import EllipticCurve.Curve.Config;
import ChameleonHash.Components.PublicKey;

public abstract class PublicParam<
        MSK extends MasterSecretKey,
        SK extends SecretKey,
        ID extends Identity,
        M extends Message,
        H extends HashValue<H>,
        R extends Randomness
        > extends ChameleonHash.Components.PublicParam<MSK, PublicKey, SK, ID, M, H, R> {
    protected PublicParam(Config config) {
        super(config);
    }

    public abstract M createMessage(String msg);

    public abstract ID createIdentity(String ID);

    public abstract MSK createMasterSecretKey();

    @Override
    public final PublicKey createPublicKey() {
        throw new RuntimeException("IBCH 没有公钥模块");
    }

    public abstract SK createSecretKey();

    public abstract H createHashValue();

    public abstract R createRandomness();
}
