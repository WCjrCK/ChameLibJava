package Encryption.ABE.MAABE;

import Encryption.ABE.ABEConfig;
import Encryption.ABE.Interface.MAABE;

public class MAABEFactory {
    private MAABEFactory() {}
    public static MAABE createMAABE(ABEConfig abeConfig) {
        try {
            assert (abeConfig.abeName.multi_auth);
            return (MAABE) abeConfig.abeName.schemeClass.getDeclaredConstructor().newInstance();
        } catch (Exception e) {
            throw new IllegalArgumentException("尚未支持当前方案：" + abeConfig.abeName.name());
        }
    }
}
