package utils;

import ChameleonHash.CH.CH;
import ChameleonHash.Interface.BaseCH;
import ChameleonHash.PBCH.Components.Attributes;
import Commitment.NIZK_DL.Proof;
import Commitment.NIZK_DL.Scheme;
import EllipticCurve.Curve.Curve;
import EllipticCurve.Curve.CurveGroup;
import EllipticCurve.Point.Point;
import EllipticCurve.Point.Scalar;
import Encryption.ABE.BaseABE.FAME.FAMECore;
import Encryption.ABE.BaseABE.FAME.MasterPublicKey;
import Encryption.ABE.BaseABE.FAME.MasterSecretKey;
import Encryption.PKE.Components.*;
import Encryption.PKE.PKE;
import Encryption.SE.SE;

import java.lang.reflect.Array;
import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.util.*;

import static EllipticCurve.Curve.CurveGroup.*;

public class ElementCounter {
    CurveGroup[] idxgroup = {G1, G2, GT, Zp};
    int[] count;
    List<String> countName = new ArrayList<>();
    HashMap<Object, Integer> type_id = new HashMap<>();
    Set<Class<?>> skip_class = new HashSet<>();

    public ElementCounter () {
        int i = 0;
        type_id.put(G1, i++);
        countName.add("G1");
        type_id.put(G2, i++);
        countName.add("G2");
        type_id.put(GT, i++);
        countName.add("GT");
        type_id.put(Zp, i++);
        countName.add("Zp");
        {
            type_id.put(PublicParam.class, i++);
            countName.add("PKE_pp");
            type_id.put(PublicKey.class, i++);
            countName.add("PKE_pk");
            type_id.put(SecretKey.class, i++);
            countName.add("PKE_sk");
            type_id.put(CipherText.class, i++);
            countName.add("PKE_ct");
            type_id.put(PlainText.class, i++);
            countName.add("PKE_pt");
        }

        {
            type_id.put(ChameleonHash.CH.Components.PublicParam.class, i++);
            countName.add("CH_pp");
            type_id.put(ChameleonHash.CH.Components.PublicKey.class, i++);
            countName.add("CH_pk");
            type_id.put(ChameleonHash.CH.Components.SecretKey.class, i++);
            countName.add("CH_sk");
            type_id.put(ChameleonHash.CH.Components.Message.class, i++);
            countName.add("CH_m");
            type_id.put(ChameleonHash.CH.Components.HashValue.class, i++);
            countName.add("CH_h");
            type_id.put(ChameleonHash.CH.Components.Randomness.class, i++);
            countName.add("CH_r");
        }

        {
            type_id.put(Encryption.ABE.BaseABE.FAME.PublicParam.class, i++);
            countName.add("FAME_pp");
            type_id.put(MasterPublicKey.class, i++);
            countName.add("FAME_mpk");
            type_id.put(MasterSecretKey.class, i++);
            countName.add("FAME_msk");
            type_id.put(Encryption.ABE.BaseABE.FAME.SecretKey.class, i++);
            countName.add("FAME_sk");
            type_id.put(Encryption.ABE.BaseABE.FAME.CipherText.class, i++);
            countName.add("FAME_ct");
            type_id.put(Encryption.ABE.BaseABE.FAME.PlainText.class, i++);
            countName.add("FAME_pt");
            type_id.put(Encryption.ABE.BaseABE.FAME.PlainText.class, i++);
            countName.add("FAME_pt");
        }

        {
            type_id.put(Encryption.SE.Components.PublicParam.class, i++);
            countName.add("SE_pp");
            type_id.put(Encryption.SE.Components.SecretKey.class, i++);
            countName.add("SE_sk");
            type_id.put(Encryption.SE.Components.CipherText.class, i++);
            countName.add("SE_ct");
            type_id.put(Encryption.SE.Components.PlainText.class, i++);
            countName.add("SE_pt");
        }

        type_id.put(Proof.class, i++);
        countName.add("NIZK_DL");

        type_id.put(Commitment.NIZK_DH_PAIR.Proof.class, i++);
        countName.add("NIZK_DL_PAIR");

        skip_class.add(String.class);
        skip_class.add(Integer.class);
        skip_class.add(BitSet.class);
        skip_class.add(CurveGroup.class);
        skip_class.add(Scheme.class);
        skip_class.add(Commitment.NIZK_DH_PAIR.Scheme.class);
        skip_class.add(PKE.class);
        skip_class.add(BaseCH.class);
        skip_class.add(FAMECore.class);
        skip_class.add(CH.class);
        skip_class.add(Random.class);
        skip_class.add(SE.class);
        skip_class.add(Curve.class);
        skip_class.add(Attributes.class);
        skip_class.add(ChameleonHash.PBCH.Components.SecretKey.class);

        count = new int[countName.size()];
    }

    private boolean countP(Point p) {
        if (type_id.containsKey(p.group())) {
            count[type_id.get(p.group())]++;
            return true;
        }
        return false;
    }

    private boolean isPoint(Class<?> c) {
        return Point.class.isAssignableFrom(c);
    }

    private boolean isScalar(Class<?> c) {
        return Scalar.class.isAssignableFrom(c);
    }

    private boolean isCollection(Class<?> c) {
        return java.util.Collection.class.isAssignableFrom(c);
    }

    private boolean tryCountObject(Object c) {
        if(isPoint(c.getClass())) {
            return countP((Point) c);
        } else if(isScalar(c.getClass())) {
            count[type_id.get(Zp)]++;
            return true;
        } else {
            for(Map.Entry<Object, Integer> e : type_id.entrySet()) {
                if (e.getKey().getClass() != CurveGroup.class) {
                    if (((Class<?>) e.getKey()).isAssignableFrom(c.getClass())) {
                        count[e.getValue()]++;
                        return true;
                    }
                }
            }

            for(Class<?> C : skip_class) {
                if(C.isAssignableFrom(c.getClass())) return true;
            }
        }
        return false;
    }

    public void count(Object c) {
        if (c == null) return;
        countClassFields(c, c.getClass());
    }

    private void countClassFields(Object target, Class<?> currentClass) {
        if (currentClass == null || currentClass == Object.class || currentClass.isPrimitive()) return;
        countClassFields(target, currentClass.getSuperclass());

        for (Field f : currentClass.getDeclaredFields()) {
            if (Modifier.isStatic(f.getModifiers()) || f.isSynthetic()) continue;
            f.setAccessible(true);
            Class<?> t = f.getType();
            if (t.isPrimitive()) return;
            try {
                Object value = f.get(target);
                if (value == null) continue;
                if(t.isArray()) {
                    int length = Array.getLength(value);
                    for (int i = 0; i < length; ++i) {
                        Object element = Array.get(value, i);
                        if (element != null && !tryCountObject(element)) count(element);
                    }
                } else if(isCollection(t)) {
                    Collection<?> v = (Collection<?>) value;
                    for (Object o : v) if(o != null && !tryCountObject(o)) count(o);
                } else {
                    if(!tryCountObject(value)) System.out.println("未知类型： " + t + " ,可能出现统计错误");
                }
            } catch (Exception ignored) {}
        }
    }

    public void add(ElementCounter o) {
        for (int i = 0;i < count.length;++i) count[i] += o.count[i];
    }

    @Override
    public String toString() {
        StringBuilder res = new StringBuilder();
        for (int i = 0;i < count.length;++i) {
            if (count[i] > 0) {
                if (res.length() > 0) res.append(" + ");
                if (count[i] > 1) res.append(count[i]);
                res.append(countName.get(i));
            }
        }
        if (res.length() == 0) return "-";
        return res.toString();
    }
}
