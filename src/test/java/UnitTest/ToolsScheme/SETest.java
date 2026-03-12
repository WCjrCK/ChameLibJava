package UnitTest.ToolsScheme;

import Encryption.Components.CipherText;
import Encryption.Components.PlainText;
import Encryption.Components.PublicParam;
import Encryption.Components.SecretKey;
import Encryption.SE;
import Encryption.SEFactory;
import Encryption.SEName;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

public class SETest {
    @DisplayName("test encryption scheme")
    @ParameterizedTest(name = "test scheme {0}")
    @EnumSource
    void SETest(SEName seName) {
        Map<String, Object> params = new HashMap<>();
        params.put("algorithm", "AES");
        params.put("transformation", "AES/ECB/PKCS5Padding");
        SE scheme = SEFactory.createSE(seName, params);
        PublicParam pp = scheme.createPublicParam(params);
        SecretKey sk1 = scheme.createSecretKey();
        SecretKey sk2 = scheme.createSecretKey();

        PlainText pt1 = scheme.createPlainText("msg111");
        PlainText pt2 = scheme.createPlainText("msg222");

        CipherText ct1 = scheme.createCipherText();
        CipherText ct2 = scheme.createCipherText();

        scheme.Encrypt(ct1, pp, sk1, pt1);
        scheme.Encrypt(ct2, pp, sk2, pt2);

        assertNotSame(ct1, ct2);

        PlainText pt = scheme.createPlainText("");
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
}
