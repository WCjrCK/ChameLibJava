package Encryption.AES;

import utils.ElementCounter;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.util.Map;

public class PublicParam extends Encryption.Components.PublicParam {
    String algorithm, transformation;

    protected PublicParam(Map<String, Object> params) {
        super(params);
        if(!params.containsKey("algorithm")) throw new IllegalArgumentException("必须指定加密算法（algorithm）");
        if(!params.containsKey("transformation")) throw new IllegalArgumentException("必须指定加密及编码格式（transformation）");
        algorithm = params.get("algorithm").toString();
        transformation = params.get("transformation").toString();
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
