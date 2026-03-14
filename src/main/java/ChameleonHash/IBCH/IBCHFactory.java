package ChameleonHash.IBCH;

import ChameleonHash.Config;
import ChameleonHash.SchemeType;

public class IBCHFactory {
    private IBCHFactory() {}

    public static ChameleonHash.IBCH.IBCH<?,?,?,?,?,?,?> createScheme(Config config) {
        try {
            assert config.schemeName.schemeType == SchemeType.IBCH;
            return (IBCH<?,?,?,?,?,?,?>) config.schemeName.schemeClass.getDeclaredConstructor().newInstance();
        } catch (Exception e) {
            throw new IllegalArgumentException("尚未支持当前方案：" + config.schemeName.name());
        }
    }
}
