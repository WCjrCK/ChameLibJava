package ChameleonHash.CH;

import ChameleonHash.Config;

public class CHFactory {
    private CHFactory() {}

    public static CH<?,?,?,?,?,?> createScheme(Config config) {
        switch (config.schemeName) {}
        throw new IllegalArgumentException("尚未支持当前方案：" + config.schemeName.name());
    }
}
