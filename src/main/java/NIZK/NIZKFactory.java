package NIZK;

import NIZK.Components.Proof;
import NIZK.Components.Relation;

public class NIZKFactory {
    private NIZKFactory() {}

    public static Proof createProof(NIZKConfig config, Relation data) {
        switch (config.scheme) {
            case DL: return NIZK.DL.Scheme.Commitment(config, (NIZK.DL.Relation) data);
            case EQUAL_DL: return NIZK.EQUAL_DL.Scheme.Commitment(config, (NIZK.EQUAL_DL.Relation) data);
            case REPRESENT: return NIZK.REPRESENT.Scheme.Commitment(config, (NIZK.REPRESENT.Relation) data);
            case DH_PAIR: return NIZK.DH_PAIR.Scheme.Commitment(config, (NIZK.DH_PAIR.Relation) data);
        }
        throw new IllegalArgumentException("尚未支持当前方案：" + config.scheme.name());
    }
}
