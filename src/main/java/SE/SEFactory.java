package SE;

import scheme.Scheme;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

public class SEFactory {
    private SEFactory() {}
    public static Scheme createScheme(SEName seName, Map<String, Object> params) {
        Collections.unmodifiableMap(new LinkedHashMap<>(
                Objects.requireNonNull(params, "方案参数不能为空")
        ));
        switch (seName) {
//            case AES: return ;
            default: throw new IllegalArgumentException("尚未支持当前方案：" + seName.name());
        }
    }

}
