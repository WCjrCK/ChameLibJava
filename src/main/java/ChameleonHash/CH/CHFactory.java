package ChameleonHash.CH;

import ChameleonHash.CH.LabelCH.LabelCHFactory;
import ChameleonHash.Config;
import ChameleonHash.SchemeType;

public class CHFactory {
    private CHFactory() {}

    public static CH createScheme(Config config) {
        try {
            assert config.schemeName.schemeType == SchemeType.CH;
            if (config.schemeName.has_label) return (CH) LabelCHFactory.createScheme(config);
            return (CH) config.schemeName.schemeClass.getDeclaredConstructor().newInstance();
        } catch (Exception e) {
            throw new IllegalArgumentException("尚未支持当前方案：" + config.schemeName.name());
        }
    }
}
