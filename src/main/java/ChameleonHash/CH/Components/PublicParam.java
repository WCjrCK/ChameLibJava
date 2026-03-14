package ChameleonHash.CH.Components;

import EllipticCurve.Curve.Config;
import ChameleonHash.Components.Identity;
import ChameleonHash.Components.MasterSecretKey;
import ChameleonHash.Components.PublicKey;
import utils.ElementCounter;

public abstract class PublicParam<
        PK extends PublicKey,
        SK extends SecretKey,
        M extends Message,
        H extends HashValue<H>,
        R extends Randomness
        > extends ChameleonHash.Components.PublicParam<MasterSecretKey, PK, SK, Identity, M, H, R> {
    protected PublicParam(Config config) {
        super(config);
    }

    public abstract M createMessage(String msg);
    @Override
    public final Identity createIdentity(String ID) {
        throw new RuntimeException("CH 没有身份模块");
    }

    @Override
    public final MasterSecretKey createMasterSecretKey() {
        throw new RuntimeException("CH 没有主密钥模块");
    }

    public abstract SK createSecretKey();

    public abstract H createHashValue();

    public abstract R createRandomness();

    public abstract String toString();

    public abstract ElementCounter TheoSize();
}
