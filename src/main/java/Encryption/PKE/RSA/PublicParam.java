package Encryption.PKE.RSA;

import utils.ElementCounter;

import java.util.Map;

public class PublicParam extends Encryption.PKE.Components.PublicParam<PublicKey, SecretKey, PlainText, CipherText> {
    int p_bit = 1024, q_bit = 1024, e_bit = -1;

    protected PublicParam(Map<String, Object> params) {
        super();
        if(params.containsKey("p_bit")) p_bit = (int) params.get("p_bit");
        if(params.containsKey("q_bit")) q_bit = (int) params.get("q_bit");
        if(params.containsKey("e_bit")) e_bit = (int) params.get("e_bit");
    }

    @Override
    public final PublicKey createPublicKey() {
        return new PublicKey();
    }
    @Override
    public final SecretKey createSecretKey() {
        return new SecretKey();
    }

    @Override
    public final PlainText createPlainText(String m) {
        return new PlainText(m);
    }

    @Override
    public final CipherText createCipherText() {
        return new CipherText();
    }

    @Override
    public final ElementCounter TheoSize() {
        ElementCounter res = new ElementCounter();
        res.count(this);
        return res;
    }
}
