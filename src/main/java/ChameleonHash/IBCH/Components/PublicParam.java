package ChameleonHash.IBCH.Components;

import EllipticCurve.Curve.Config;

public abstract class PublicParam<
        MSK extends MasterSecretKey,
        SK extends SecretKey,
        M extends Message,
        I extends Identity,
        H extends HashValue<H>,
        R extends Randomness
        > extends ChameleonHash.Components.PublicParam<SK, M, H, R> {
    protected PublicParam(Config config) {
        super(config);
    }

    public abstract MSK createMasterSecretKey();

    public abstract SK createSecretKey();

    public abstract M createMessage(String msg);

    public abstract I createIdentity(String ID);

    public abstract H createHashValue();

    public abstract R createRandomness();
}
