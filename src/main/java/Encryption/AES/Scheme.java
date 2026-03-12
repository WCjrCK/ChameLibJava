package Encryption.AES;

import Encryption.SE;

import javax.crypto.Cipher;
import java.nio.charset.StandardCharsets;
import java.util.Map;

public class Scheme extends SE {

    @Override
    public final PublicParam createPublicParam(Map<String, Object> params) {
        return new PublicParam(params);
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

    private void Encrypt(CipherText ct, PublicParam pp, SecretKey sk, PlainText pt) {
        try {
            ct.ct = pp.getCipher(Cipher.ENCRYPT_MODE, sk.key).doFinal(pt.pt);
        } catch (Exception e) {
            ct.ct = e.getMessage().getBytes(StandardCharsets.UTF_8);
        }
    }

    @Override
    public void Encrypt(Encryption.Components.CipherText ct, Encryption.Components.PublicParam pp, Encryption.Components.SecretKey sk, Encryption.Components.PlainText pt) {
        if(!(ct instanceof CipherText)) throw new IllegalArgumentException("密文不适配当前方案");
        if(!(pp instanceof PublicParam)) throw new IllegalArgumentException("密文不适配当前方案");
        if(!(sk instanceof SecretKey)) throw new IllegalArgumentException("密文不适配当前方案");
        if(!(pt instanceof PlainText)) throw new IllegalArgumentException("密文不适配当前方案");
        Encrypt((CipherText) ct, (PublicParam) pp, (SecretKey) sk, (PlainText) pt);
    }

    private void Decrypt(PlainText pt, PublicParam pp, SecretKey sk, CipherText ct) {
        try {
            pt.pt = pp.getCipher(Cipher.DECRYPT_MODE, sk.key).doFinal(ct.ct);
        } catch (Exception e) {
            pt.pt = e.getMessage().getBytes(StandardCharsets.UTF_8);
        }
    }

    @Override
    public void Decrypt(Encryption.Components.PlainText pt, Encryption.Components.PublicParam pp, Encryption.Components.SecretKey sk, Encryption.Components.CipherText ct) {
        if(!(ct instanceof CipherText)) throw new IllegalArgumentException("密文不适配当前方案");
        if(!(pp instanceof PublicParam)) throw new IllegalArgumentException("密文不适配当前方案");
        if(!(sk instanceof SecretKey)) throw new IllegalArgumentException("密文不适配当前方案");
        if(!(pt instanceof PlainText)) throw new IllegalArgumentException("密文不适配当前方案");
        Decrypt((PlainText) pt, (PublicParam) pp, (SecretKey) sk, (CipherText) ct);
    }
}
