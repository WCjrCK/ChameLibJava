package NIZK.DL;

import NIZK.NIZKConfig;

public class Scheme {
    public static Proof Commitment(NIZKConfig config, Relation data) {
        if(!data.g.pow(data.x).isEqual(data.y)) throw new RuntimeException("输入数据不满足 g^x == y");
        Proof res = new Proof();
        res.curve = config.curve;
        res.gamma = config.curve.getRandomScalar();
        res.alpha = data.g.pow(res.gamma);
        res.gamma = res.H(String.format("%s|%s", data.y, res.alpha)).mul(data.x).add(res.gamma);
        return res;
    }
}
