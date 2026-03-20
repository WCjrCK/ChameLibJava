package Commitment.REPRESENT;

import Commitment.NIZKConfig;
import EllipticCurve.Point.Scalar;

public class Scheme {
    public static Proof Commitment(NIZKConfig config, Witness data) {
        if(!data.y.isEqual(data.g_1.pow(data.x_1).mul(data.g_2.pow(data.x_2)))) throw new RuntimeException("输入数据不满足 y == g_1^x_1 * g_2^x_2");
        Proof res = new Proof();
        res.curve = config.curve;
        res.gamma_1 = config.curve.getRandomScalar();
        res.gamma_2 = config.curve.getRandomScalar();
        res.alpha = data.g_1.pow(res.gamma_1).mul(data.g_2.pow(res.gamma_2));
        Scalar beta = res.H(String.format("%s|%s|%s|%s", data.y, data.g_1, data.g_2, res.alpha));
        res.gamma_1 = beta.mul(data.x_1).add(res.gamma_1);
        res.gamma_2 = beta.mul(data.x_2).add(res.gamma_2);
        return res;
    }
}
