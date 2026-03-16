package ChameleonHash.PBCH.BasePBCH;

import ChameleonHash.Interface.BasePBCH;
import ChameleonHash.PBCH.Components.*;
import ChameleonHash.PBCH.PBCH;

public abstract class Scheme<
        PP extends PublicParam<MPK, MSK, SK, P, A, M, H, R>,
        MPK extends MasterSecretKey,
        MSK extends MasterSecretKey,
        SK extends SecretKey,
        P extends Policy,
        A extends Attributes,
        M extends Message,
        H extends HashValue<H>,
        R extends Randomness
        > extends PBCH<PP, MPK, MSK, SK, P, A, M, H, R>
        implements BasePBCH<PP, MPK, MSK, SK, P, A, M, H, R> {
}
