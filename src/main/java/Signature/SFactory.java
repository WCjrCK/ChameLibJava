package Signature;

import Signature.BLS.Scheme;

public class SFactory {
    private SFactory() {}

    public static S createS(Config config) {
        switch (config.sName) {
            case BLS: return new Scheme();
            default: throw new IllegalArgumentException("尚未支持当前方案：" + config.sName.name());
        }
    }
}
