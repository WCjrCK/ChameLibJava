package UnitTest.ToolsScheme;

import Encryption.Components.CipherText;
import Encryption.Components.PlainText;
import Encryption.Components.PublicParam;
import Encryption.Components.SecretKey;
import Encryption.PKE.Components.PublicKey;
import Encryption.PKE.PKE;
import Encryption.PKE.PKEConfig;
import Encryption.PKE.PKEFactory;
import Encryption.PKE.PKEName;
import Encryption.SE.SE;
import Encryption.SE.SEConfig;
import Encryption.SE.SEFactory;
import Encryption.SE.SEName;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

public class EncryptionTest {
    @DisplayName("test symmetric encryption scheme")
    @ParameterizedTest(name = "test scheme {0}")
    @EnumSource
    void SETest(SEName seName) {
        Map<String, Object> params = new HashMap<>();
        params.put("algorithm", "AES");
        params.put("transformation", "AES/ECB/PKCS5Padding");
        SEConfig seConfig = new SEConfig(seName, params);
        SE scheme = SEFactory.createSE(seConfig);
        PublicParam pp = scheme.createPublicParam(seConfig);
        SecretKey sk1 = pp.createSecretKey();
        scheme.KeyGen(sk1, pp);
        SecretKey sk2 = pp.createSecretKey();
        scheme.KeyGen(sk2, pp);

        PlainText pt1 = pp.createPlainText("msg1");
        PlainText pt2 = pp.createPlainText("msg2");

        CipherText ct1 = pp.createCipherText();
        CipherText ct2 = pp.createCipherText();

        scheme.Encrypt(ct1, pp, sk1, pt1);
        scheme.Encrypt(ct2, pp, sk2, pt2);

        assertNotSame(ct1, ct2);

        PlainText pt = pp.createPlainText("");
        scheme.Decrypt(pt, pp, sk1, ct1);
        assertTrue(pt.isEqual(pt1));
        assertFalse(pt.isEqual(pt2));
        scheme.Decrypt(pt, pp, sk2, ct2);
        assertTrue(pt.isEqual(pt2));
        assertFalse(pt.isEqual(pt1));
        scheme.Decrypt(pt, pp, sk1, ct2);
        assertFalse(pt.isEqual(pt2));
        assertFalse(pt.isEqual(pt1));
    }

    @DisplayName("test asymmetric encryption scheme")
    @ParameterizedTest(name = "test scheme {0}")
    @EnumSource
    void AETest(PKEName PKEName) {
        Map<String, Object> params = new HashMap<>();
//        params.put("algorithm", "AES");
//        params.put("transformation", "AES/ECB/PKCS5Padding");
        PKEConfig pkeConfig = new PKEConfig(PKEName, params);
        PKE scheme = PKEFactory.createPKE(pkeConfig);
        Encryption.PKE.Components.PublicParam pp = scheme.createPublicParam(params);
        PublicKey pk1 = pp.createPublicKey();
        SecretKey sk1 = pp.createSecretKey();

        scheme.KeyGen(pk1, sk1, pp);

        PublicKey pk2 = pp.createPublicKey();
        SecretKey sk2 = pp.createSecretKey();

        scheme.KeyGen(pk2, sk2, pp);

        PlainText pt1 = pp.createPlainText("msg1");
        PlainText pt2 = pp.createPlainText("msg2");

        CipherText ct1 = pp.createCipherText();
        CipherText ct2 = pp.createCipherText();

        scheme.Encrypt(ct1, pp, pk1, pt1);
        scheme.Encrypt(ct2, pp, pk2, pt2);

        assertNotSame(ct1, ct2);

        PlainText pt = pp.createPlainText("");
        scheme.Decrypt(pt, pp, pk1, sk1, ct1);
        assertTrue(pt.isEqual(pt1));
        assertFalse(pt.isEqual(pt2));
        scheme.Decrypt(pt, pp, pk2, sk2, ct2);
        assertTrue(pt.isEqual(pt2));
        assertFalse(pt.isEqual(pt1));
        scheme.Decrypt(pt, pp, pk1, sk1, ct2);
        assertFalse(pt.isEqual(pt2));
        assertFalse(pt.isEqual(pt1));
    }
}
