package Encryption.ABE.BaseABE;

import Encryption.ABE.ABEConfig;
import Encryption.ABE.Interface.BaseABE;

public class BaseABEFactory {
    private BaseABEFactory() {}
    public static BaseABE createBaseABE(ABEConfig abeConfig) {
        try {
            assert ((!abeConfig.abeName.revokable));
            return (BaseABE) abeConfig.abeName.schemeClass.getDeclaredConstructor().newInstance();
        } catch (Exception e) {
            throw new IllegalArgumentException("尚未支持当前方案：" + abeConfig.abeName.name());
        }
    }
}
