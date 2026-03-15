package ChameleonHash.IBCH.LabelIBCH;

import ChameleonHash.Config;
import ChameleonHash.Interface.LabelIBCH;
import ChameleonHash.SchemeType;

public class LabelIBCHFactory {
    private LabelIBCHFactory() {}

    public static LabelIBCH createScheme(Config config) {
        try {
            assert config.schemeName.schemeType == SchemeType.IBCH && config.schemeName.has_label;
            return (LabelIBCH) config.schemeName.schemeClass.getDeclaredConstructor().newInstance();
        } catch (Exception e) {
            throw new IllegalArgumentException("尚未支持当前方案：" + config.schemeName.name());
        }
    }
}
