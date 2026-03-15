package ChameleonHash;

import ChameleonHash.Components.*;

public abstract class Scheme<
        PP extends PublicParam<SK, M, H, R>,
        SK extends SecretKey,
        M extends Message,
        H extends HashValue<H>,
        R extends Randomness
        > {
}
