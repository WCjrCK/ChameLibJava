package ChameleonHash.PBCH.BAPBCH.Components;

import EllipticCurve.Curve.Config;

public abstract class PublicParam<
        MPK extends ChameleonHash.PBCH.Components.MasterPublicKey,
        MSK extends ChameleonHash.PBCH.Components.MasterSecretKey,
        SK extends ChameleonHash.PBCH.Components.SecretKey,
        P extends ChameleonHash.PBCH.Components.Policy,
        A extends ChameleonHash.PBCH.Components.Attributes,
        U extends User,
        M extends ChameleonHash.PBCH.Components.Message,
        H extends ChameleonHash.PBCH.Components.HashValue<H>,
        R extends ChameleonHash.PBCH.Components.Randomness
        >
        extends ChameleonHash.PBCH.Components.PublicParam<MPK, MSK, SK, P, A, M, H, R> {
    protected PublicParam(Config config) {
        super(config);
    }

    public abstract U createUser(int id_len);

    public abstract U createUser(U user, int id_len);
}
