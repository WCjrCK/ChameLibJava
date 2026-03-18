package ChameleonHash.PBCH.RevocablePBCH;

import ChameleonHash.Interface.RevocablePBCH;
import ChameleonHash.PBCH.PBCHConfig;

public class RevocablePBCHFactory {
    private RevocablePBCHFactory() {}

    public static RevocablePBCH createScheme(PBCHConfig config) {
        try {
            return (RevocablePBCH) config.schemeName.schemeClass.getDeclaredConstructor().newInstance();
        } catch (Exception e) {
            throw new IllegalArgumentException("尚未支持当前方案：" + config.schemeName.name());
        }
    }
}
