package scheme.IBCH.Components;

import EllipticCurve.Curve.Config;
import scheme.Components.PublicKey;

public abstract class PublicParam<
        MSK extends MasterSecretKey,
        SK extends SecretKey,
        ID extends Identity,
        M extends Message,
        H extends HashValue<H>,
        R extends Randomness
        > extends scheme.Components.PublicParam<MSK, PublicKey, SK, ID, M, H, R> {
    protected PublicParam(Config config) {
        super(config);
    }

    public abstract M createMessage(String msg);

    public abstract ID createIdentity(String ID);

    public abstract MSK createMasterSecretKey();

    public abstract SK createSecretKey();

    public abstract H createHashValue();

    public abstract R createRandomness();
}
