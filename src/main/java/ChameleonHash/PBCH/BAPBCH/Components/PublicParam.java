package ChameleonHash.PBCH.BAPBCH.Components;

import ChameleonHash.PBCH.BasePBCH.Components.*;
import EllipticCurve.Curve.Config;

public abstract class PublicParam<
        MPK extends MasterPublicKey,
        MSK extends MasterSecretKey,
        SK extends SecretKey,
        P extends Policy,
        A extends Attributes,
        U extends User,
        M extends Message,
        H extends HashValue<H>,
        R extends Randomness
        >
        extends ChameleonHash.PBCH.BasePBCH.Components.PublicParam<MPK, MSK, SK, P, A, M, H, R> {
    protected PublicParam(Config config) {
        super(config);
    }

    public abstract U createUser(int id_len);

    public abstract U createUser(U user, int id_len);
}
