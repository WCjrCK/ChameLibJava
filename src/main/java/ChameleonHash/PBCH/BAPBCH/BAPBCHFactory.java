package ChameleonHash.PBCH.BAPBCH;

import ChameleonHash.Interface.BAPBCH;
import ChameleonHash.PBCH.PBCHConfig;

public class BAPBCHFactory {
    private BAPBCHFactory() {}

    public static BAPBCH createScheme(PBCHConfig config) {
        try {
            assert config.schemeName.has_blackbox_accountability;
            return (BAPBCH) config.schemeName.schemeClass.getDeclaredConstructor().newInstance();
        } catch (Exception e) {
            throw new IllegalArgumentException("尚未支持当前方案：" + config.schemeName.name());
        }
    }
}
