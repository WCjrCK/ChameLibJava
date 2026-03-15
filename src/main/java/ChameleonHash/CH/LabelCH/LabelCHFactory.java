package ChameleonHash.CH.LabelCH;

import ChameleonHash.Config;
import ChameleonHash.Interface.LabelCH;
import ChameleonHash.SchemeType;

public class LabelCHFactory {
    private LabelCHFactory() {}

    public static LabelCH createScheme(Config config) {
        try {
            assert config.schemeName.schemeType == SchemeType.CH && config.schemeName.has_label;
            return (LabelCH) config.schemeName.schemeClass.getDeclaredConstructor().newInstance();
        } catch (Exception e) {
            throw new IllegalArgumentException("尚未支持当前方案：" + config.schemeName.name());
        }
    }
}
