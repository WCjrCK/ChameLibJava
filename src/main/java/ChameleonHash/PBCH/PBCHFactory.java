package ChameleonHash.PBCH;

public class PBCHFactory {
    private PBCHFactory() {}

    public static PBCH createScheme(PBCHConfig config) {
//        try {
//            if (config.schemeName.has_label) return (PBCH) LabelCHFactory.createScheme(config);
//            return (PBCH) config.schemeName.schemeClass.getDeclaredConstructor().newInstance();
//        } catch (Exception e) {
            throw new IllegalArgumentException("尚未支持当前方案：" + config.schemeName.name());
//        }
    }
}
