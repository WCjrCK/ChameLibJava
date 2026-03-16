package utils;

import Commitment.DL.NIZK_DL.Proof;
import Commitment.NIZK;
import EllipticCurve.Curve.CurveGroup;
import EllipticCurve.Point.Point;
import EllipticCurve.Point.Scalar;
import Encryption.PKE.Components.*;
import Encryption.PKE.PKE;

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

        type_id.put(Proof.class, i++);
        countName.add("NIZK_DL");

        skip_class.add(String.class);
        skip_class.add(Integer.class);
        skip_class.add(BitSet.class);
        skip_class.add(CurveGroup.class);
        skip_class.add(NIZK.class);
        skip_class.add(PKE.class);

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
        if(tryCountObject(c)) return;
        for (java.lang.reflect.Field f : c.getClass().getDeclaredFields()) {
            f.setAccessible(true);
            Class<?> t = f.getType();
            try {
                if(t.isArray()) {
                    Object[] v = (Object[]) f.get(c);
                    for (Object o : v) if(!tryCountObject(o)) count(o);
                } else if(isCollection(t)) {
                    Collection<?> v = (Collection<?>) f.get(c);
                    for (Object o : v) if(!tryCountObject(o)) count(o);
                } else {
                    if(!tryCountObject(f.get(c))) System.out.println("未知类型： " + t + " ,可能出现统计错误");
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
