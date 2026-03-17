package ChameleonHash.CH.Components;

import EllipticCurve.Curve.Config;
import EllipticCurve.Curve.Curve;
import EllipticCurve.Curve.CurveFactory;
import utils.ElementCounter;

public abstract class PublicParam<
        PK extends PublicKey,
        SK extends SecretKey,
        M extends Message,
        H extends HashValue<H>,
        R extends Randomness
        > {
    public final Curve curve;
    protected PublicParam(Config config) {
        curve = CurveFactory.create(config);
    }

    public abstract M createMessage(String msg);

    public abstract PK createPublicKey();

    public abstract SK createSecretKey();

    public abstract H createHashValue();

    public abstract R createRandomness();

    public byte[] serializePublicKey(PK target) {
        throw new UnsupportedOperationException("当前方案未实现 PublicKey 序列化");
    }

    public void deserializePublicKey(PK target, byte[] data) {
        throw new UnsupportedOperationException("当前方案未实现 PublicKey 反序列化");
    }

    public byte[] serializeSecretKey(SK target) {
        throw new UnsupportedOperationException("当前方案未实现 SecretKey 序列化");
    }

    public void deserializeSecretKey(SK target, byte[] data) {
        throw new UnsupportedOperationException("当前方案未实现 SecretKey 反序列化");
    }

    public byte[] serializeMessage(M target) {
        throw new UnsupportedOperationException("当前方案未实现 Message 序列化");
    }

    public void deserializeMessage(M target, byte[] data) {
        throw new UnsupportedOperationException("当前方案未实现 Message 反序列化");
    }

    public byte[] serializeHashValue(H target) {
        throw new UnsupportedOperationException("当前方案未实现 HashValue 序列化");
    }

    public void deserializeHashValue(H target, byte[] data) {
        throw new UnsupportedOperationException("当前方案未实现 HashValue 反序列化");
    }

    public byte[] serializeRandomness(R target) {
        throw new UnsupportedOperationException("当前方案未实现 Randomness 序列化");
    }

    public void deserializeRandomness(R target, byte[] data) {
        throw new UnsupportedOperationException("当前方案未实现 Randomness 反序列化");
    }

    public abstract String toString();

    public abstract ElementCounter TheoSize();
}
