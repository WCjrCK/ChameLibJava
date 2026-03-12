package Encryption.AES;

import utils.ElementCounter;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

public class PlainText extends Encryption.Components.PlainText {
    public byte[] pt;

    PlainText(String m) {
        pt = m.getBytes(StandardCharsets.UTF_8);
    }

    @Override
    public final boolean isEqual(Encryption.Components.PlainText o) {
        if(o instanceof PlainText) return Arrays.equals(pt, ((PlainText) o).pt);
        return false;
    }

    @Override
    public final ElementCounter TheoSize() {
        ElementCounter res = new ElementCounter();
        res.count(this);
        return res;
    }

    @Override
    public final String toString() {
        return "pt = " + Arrays.toString(pt);
    }
}
