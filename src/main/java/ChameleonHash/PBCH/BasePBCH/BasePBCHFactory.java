package ChameleonHash.PBCH.BasePBCH;

import ChameleonHash.Interface.BasePBCH;
import ChameleonHash.PBCH.PBCHConfig;

public class BasePBCHFactory {
    private BasePBCHFactory() {}

    public static BasePBCH createScheme(PBCHConfig config) {
        try {
            return (BasePBCH) config.schemeName.schemeClass.getDeclaredConstructor().newInstance();
        } catch (Exception e) {
            throw new IllegalArgumentException("尚未支持当前方案：" + config.schemeName.name());
        }
    }
}
