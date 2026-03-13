package scheme.CH.Components;

import EllipticCurve.Curve.Config;
import scheme.Components.Identity;
import scheme.Components.MasterSecretKey;
import scheme.Components.PublicKey;

public abstract class PublicParam<
        PK extends PublicKey,
        SK extends SecretKey,
        M extends Message,
        H extends HashValue<H>,
        R extends Randomness
        > extends scheme.Components.PublicParam<MasterSecretKey, PK, SK, Identity, M, H, R> {
    protected PublicParam(Config config) {
        super(config);
    }

    public abstract M createMessage(String msg);

    public abstract PK createPublicKey();

    public abstract SK createSecretKey();

    public abstract H createHashValue();

    public abstract R createRandomness();
}
