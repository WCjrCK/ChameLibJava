package ChameleonHash.CH;

import ChameleonHash.CH.LabelCH.LabelCHFactory;

public class CHFactory {
    private CHFactory() {}

    public static CH createScheme(CHConfig config) {
        try {
            if (config.schemeName.has_label) return (CH) LabelCHFactory.createScheme(config);
            return (CH) config.schemeName.schemeClass.getDeclaredConstructor().newInstance();
        } catch (Exception e) {
            throw new IllegalArgumentException("尚未支持当前方案：" + config.schemeName.name());
        }
    }
}
