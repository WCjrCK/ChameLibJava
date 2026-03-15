package Encryption.ABE;

import Encryption.ABE.FAME.Scheme;

public class ABEFactory {
    private ABEFactory() {}
    public static ABE createABE(Config config) {
        switch (config.abeName) {
            case FAME: return new Scheme();
            default: throw new IllegalArgumentException("尚未支持当前方案：" + config.abeName.name());
        }
    }

}
