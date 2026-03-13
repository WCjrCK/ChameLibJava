package scheme;

import scheme.Components.*;

public abstract class Scheme<
        PP extends PublicParam<MSK, PK, SK, ID, M, H, R>,
        MSK extends MasterSecretKey,
        PK extends PublicKey,
        SK extends SecretKey,
        ID extends Identity,
        M extends Message,
        H extends HashValue<H>,
        R extends Randomness
        > {
}
