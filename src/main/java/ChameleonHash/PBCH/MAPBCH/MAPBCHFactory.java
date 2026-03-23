package ChameleonHash.PBCH.MAPBCH;

import ChameleonHash.Interface.MAPBCH;
import ChameleonHash.PBCH.PBCHConfig;

public class MAPBCHFactory {
    private MAPBCHFactory() {}

    public static MAPBCH createScheme(PBCHConfig config) {
        try {
            assert config.schemeName.multi_auth;
            return (MAPBCH) config.schemeName.schemeClass.getDeclaredConstructor().newInstance();
        } catch (Exception e) {
            throw new IllegalArgumentException("尚未支持当前方案：" + config.schemeName.name());
        }
    }
}
