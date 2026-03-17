package Encryption.SE.AES;

import Encryption.SE.SEConfig;
import utils.ElementCounter;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

public class PublicParam extends Encryption.SE.Components.PublicParam<SecretKey, PlainText, CipherText> {
    String algorithm, transformation;

    protected PublicParam(SEConfig seConfig) {
        super();
        if(!seConfig.params.containsKey("algorithm")) throw new IllegalArgumentException("必须指定加密算法（algorithm）");
        if(!seConfig.params.containsKey("transformation")) throw new IllegalArgumentException("必须指定加密及编码格式（transformation）");
        algorithm = seConfig.params.get("algorithm").toString();
        transformation = seConfig.params.get("transformation").toString();
    }

    @Override
    public final SecretKey createSecretKey() {
        return new SecretKey();
    }

    @Override
    public SecretKey createSecretKey(byte[] sk) {
        return new SecretKey(sk);
    }

    @Override
    public final PlainText createPlainText(String m) {
        return new PlainText(m);
    }

    @Override
    public PlainText createPlainText(byte[] m) {
        return new PlainText(m);
    }

    @Override
    public final CipherText createCipherText() {
        return new CipherText();
    }

    protected Cipher getCipher(int mode, byte[] key) {
        SecretKeySpec skspec = new SecretKeySpec(key, algorithm);
        try {
            Cipher cipher = Cipher.getInstance(transformation);
            cipher.init(mode, skspec);
            return cipher;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public final ElementCounter TheoSize() {
        ElementCounter res = new ElementCounter();
        res.count(this);
        return res;
    }
}
