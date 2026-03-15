package NIZK.EQUAL_DL;

import NIZK.NIZKConfig;

public class Scheme {
    public static Proof Commitment(NIZKConfig config, Relation data) {
        if(!data.g_1.pow(data.x).isEqual(data.y_1)) throw new RuntimeException("输入数据不满足 g_1^x == y_1");
        if(!data.g_2.pow(data.x).isEqual(data.y_2)) throw new RuntimeException("输入数据不满足 g_2^x == y_2");
        Proof res = new Proof();
        res.curve = config.curve;
        res.gamma = config.curve.getRandomScalar();
        res.alpha_1 = data.g_1.pow(res.gamma);
        res.alpha_2 = data.g_2.pow(res.gamma);
        res.gamma = res.H(String.format("%s|%s|%s|%s", data.y_1, data.y_2, res.alpha_1, res.alpha_2)).mul(data.x).add(res.gamma);
        return res;
    }
}
