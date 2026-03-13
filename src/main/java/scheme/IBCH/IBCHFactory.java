package scheme.IBCH;

import scheme.Config;

public class IBCHFactory {
    private IBCHFactory() {}

    public static scheme.IBCH.IBCH createScheme(Config config) {
        try {
            return (IBCH) config.schemeName.schemeClass.getDeclaredConstructor().newInstance();
        } catch (Exception e) {
            throw new IllegalArgumentException("尚未支持当前方案：" + config.schemeName.name());
        }
    }
}
