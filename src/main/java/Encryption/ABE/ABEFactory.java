package Encryption.ABE;

import Encryption.PKE.Config;
import Encryption.PKE.PKE;

public class ABEFactory {
    private ABEFactory() {}
    public static PKE createAE(Config config) {
        switch (config.PKEName) {
            case RSA: return new Encryption.PKE.RSA.Scheme();
            default: throw new IllegalArgumentException("尚未支持当前方案：" + config.PKEName.name());
        }
    }

}
