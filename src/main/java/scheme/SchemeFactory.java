package scheme;

import scheme.CH.CHFactory;
import scheme.IBCH.IBCHFactory;

public class SchemeFactory {
    private SchemeFactory() {}

    public static Scheme<?,?,?,?,?,?,?,?> createScheme(Config config) {
        switch (config.schemeName.schemeType) {
            case CH: return CHFactory.createScheme(config);
            case IBCH: return IBCHFactory.createScheme(config);
        }
        throw new IllegalArgumentException("尚未支持当前方案：" + config.schemeName.name());
    }
}
