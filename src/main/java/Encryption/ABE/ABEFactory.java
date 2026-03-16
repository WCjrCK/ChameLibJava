package Encryption.ABE;

import Encryption.ABE.FAME.Scheme;

public class ABEFactory {
    private ABEFactory() {}
    public static ABE createABE(ABEConfig abeConfig) {
        switch (abeConfig.abeName) {
            case FAME: return new Scheme();
            default: throw new IllegalArgumentException("尚未支持当前方案：" + abeConfig.abeName.name());
        }
    }

}
