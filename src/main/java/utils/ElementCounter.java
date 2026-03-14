package utils;

import EllipticCurve.Curve.CurveGroup;
import EllipticCurve.Point.Point;
import EllipticCurve.Point.Scalar;

import java.util.*;

import static EllipticCurve.Curve.CurveGroup.*;

public class ElementCounter {
    CurveGroup[] idxgroup = {G1, G2, GT, Zp};
    int[] count;
    List<String> countName = new ArrayList<>();
    HashMap<Object, Integer> type_id = new HashMap<>();

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
        return c.isAssignableFrom(Point.class) || Point.class.isAssignableFrom(c);
    }

    private boolean isScalar(Class<?> c) {
        return c.isAssignableFrom(Scalar.class) || Scalar.class.isAssignableFrom(c);
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
        } else if(type_id.containsKey(c.getClass())) {
            count[type_id.get(c.getClass())]++;
            return true;
        } else {
            if (c.getClass() == String.class) return true;
            if (c.getClass() == Integer.class) return true;
            if (c.getClass() == BitSet.class) return true;
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
        for (int i = 0;i < idxgroup.length;++i) {
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
