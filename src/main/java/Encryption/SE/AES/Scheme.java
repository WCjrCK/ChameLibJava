package Encryption.SE.AES;

import Encryption.SE.SE;

import javax.crypto.Cipher;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.Random;

public class Scheme extends SE<PublicParam, SecretKey, PlainText, CipherText> {
    @Override
    public final PublicParam createPublicParam(Map<String, Object> params) {
        return new PublicParam(params);
    }

    @Override
    public final void KeyGen(SecretKey sk, PublicParam pp) {
        sk.key = new byte[32];
        Random rand = new Random();
        rand.nextBytes(sk.key);
    }

    @Override
    public void Encrypt(CipherText ct, PublicParam pp, SecretKey sk, PlainText pt) {
        try {
            ct.ct = pp.getCipher(Cipher.ENCRYPT_MODE, sk.key).doFinal(pt.pt);
        } catch (Exception e) {
            ct.ct = e.getMessage().getBytes(StandardCharsets.UTF_8);
        }
    }

    @Override
    public void Decrypt(PlainText pt, PublicParam pp, SecretKey sk, CipherText ct) {
        try {
            pt.pt = pp.getCipher(Cipher.DECRYPT_MODE, sk.key).doFinal(ct.ct);
        } catch (Exception e) {
            pt.pt = e.getMessage().getBytes(StandardCharsets.UTF_8);
        }
    }
}
