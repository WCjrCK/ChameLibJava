package Encryption.ABE.RevocableABE;

import Encryption.ABE.ABEConfig;
import Encryption.ABE.Interface.RevocableABE;

public class RevocableABEFactory {
    private RevocableABEFactory() {}
    public static RevocableABE createRevocableABE(ABEConfig abeConfig) {
        try {
            assert (abeConfig.abeName.revokable);
            return (RevocableABE) abeConfig.abeName.schemeClass.getDeclaredConstructor().newInstance();
        } catch (Exception e) {
            throw new IllegalArgumentException("尚未支持当前方案：" + abeConfig.abeName.name());
        }
    }
}
