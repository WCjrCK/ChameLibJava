package utils;

import EllipticCurve.Curve.CurveGroup;
import EllipticCurve.Point.Point;

import java.util.Collection;

import static EllipticCurve.Curve.CurveGroup.*;

public class ElementCounter {
    CurveGroup[] idxgroup = {G1, G2, GT, Zp};
    int[] count = new int[idxgroup.length];

    private void countP(Point p) {
        for (int i = 0;i < count.length;++i) if (p.group() == idxgroup[i]) {
            count[i] += 1;
            break;
        }
    }

    private boolean isPoint(Class<?> c) {
        return c.isAssignableFrom(Point.class) || Point.class.isAssignableFrom(c);
    }

    private boolean isCollection(Class<?> c) {
        return java.util.Collection.class.isAssignableFrom(c);
    }

    public void count(Object c) {
        if(isPoint(c.getClass())) {
            countP((Point) c);
            return;
        }
        for (java.lang.reflect.Field f : c.getClass().getDeclaredFields()) {
            f.setAccessible(true);
            Class<?> t = f.getType();

            if(isPoint(t)) {
                try {
                    Point v = (Point) f.get(c);
                    countP(v);
                } catch (Exception ignored) {}
            } else if(t.isArray()) {
                try {
                    Object[] v = (Object[]) f.get(c);
                    for (Object o : v) count(o);
                } catch (Exception ignored) {}
            } else if(isCollection(t)) {
                try {
                    Collection<?> v = (Collection<?>) f.get(c);
                    for (Object o : v) count(o);
                } catch (Exception ignored) {}
            }
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
                res.append(idxgroup[i].name());
            }
        }
        if (res.length() == 0) return "-";
        return res.toString();
    }
}
