package PerformTest;

import ChameleonHash.CH.CH;
import ChameleonHash.IBCH.IBCH;
import ChameleonHash.PBCH.PBCH;
import EllipticCurve.Curve.Curve;
import Encryption.ABE.ABE;
import Encryption.PKE.PKE;
import Encryption.SE.SE;
import Signature.S;
import org.openjdk.jol.info.ClassLayout;
import org.openjdk.jol.info.GraphLayout;

import java.io.BufferedWriter;
import java.io.IOException;
import java.lang.reflect.Array;
import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.math.BigInteger;
import java.util.*;

public final class RealStorageUtil {
    private RealStorageUtil() {}

    public static long sizeOf(Object target) {
        return sizeOf(target, new IdentityHashMap<>());
    }

    public static long rawSizeOf(Object target) {
        if (target == null) return 0L;
        return GraphLayout.parseInstance(target).totalSize();
    }

    public static String debugTopLevelBreakdown(String label, Object target) {
        if (target == null) return label + ": <null>";

        StringBuilder sb = new StringBuilder();
        sb.append(label)
                .append(": filtered=")
                .append(sizeOf(target))
                .append("B, raw=")
                .append(rawSizeOf(target))
                .append("B\n");

        for (Class<?> current = target.getClass(); current != null && current != Object.class; current = current.getSuperclass()) {
            for (Field field : current.getDeclaredFields()) {
                if (Modifier.isStatic(field.getModifiers()) || field.isSynthetic()) continue;
                try {
                    field.setAccessible(true);
                    Object value = field.get(target);
                    sb.append(current.getSimpleName())
                            .append(".")
                            .append(field.getName())
                            .append(": filtered=")
                            .append(sizeOf(value))
                            .append("B, raw=")
                            .append(rawSizeOf(value))
                            .append("B\n");
                } catch (Throwable e) {
                    sb.append(current.getSimpleName())
                            .append(".")
                            .append(field.getName())
                            .append(": <inaccessible>\n");
                }
            }
        }
        return sb.toString();
    }

    public static void writeRow(BufferedWriter writer, String curveName, long... values) throws IOException {
        writer.write(curveName);
        for (long value : values) writer.write("," + value);
        writer.write("\n");
        writer.flush();
    }

    public static void closeWriter(BufferedWriter writer) throws IOException {
        if (writer != null) writer.close();
    }

    public static void closeWriterList(List<BufferedWriter> writers) throws IOException {
        if (writers == null) return;
        for (BufferedWriter writer : writers) closeWriter(writer);
    }

    private static long sizeOf(Object target, IdentityHashMap<Object, Boolean> visited) {
        if (target == null) return 0L;
        if (shouldSkip(target)) return 0L;

        Class<?> clazz = target.getClass();
        if (isLeafType(clazz)) return rawSizeOf(target);

        if (visited.put(target, Boolean.TRUE) != null) return 0L;

        long size = shallowSize(target);

        if (clazz.isArray()) return size + referencedArraySize(target, clazz.getComponentType(), visited);
        if (target instanceof Collection<?>) return size + collectionSize((Collection<?>) target, visited);
        if (target instanceof Map<?, ?>) return size + mapSize((Map<?, ?>) target, visited);

        for (Class<?> current = clazz; current != null && current != Object.class; current = current.getSuperclass()) {
            for (Field field : current.getDeclaredFields()) {
                if (Modifier.isStatic(field.getModifiers()) || field.isSynthetic()) continue;
                if (field.getType().isPrimitive()) continue;
                try {
                    field.setAccessible(true);
                    size += sizeOf(field.get(target), visited);
                } catch (Throwable ignored) {
                    // Some JDK-internal fields may not be reflectively accessible.
                }
            }
        }
        return size;
    }

    private static long shallowSize(Object target) {
        return ClassLayout.parseInstance(target).instanceSize();
    }

    private static long referencedArraySize(Object array, Class<?> componentType, IdentityHashMap<Object, Boolean> visited) {
        if (componentType.isPrimitive()) return 0L;
        long size = 0L;
        int len = Array.getLength(array);
        for (int i = 0; i < len; ++i) size += sizeOf(Array.get(array, i), visited);
        return size;
    }

    private static long collectionSize(Collection<?> collection, IdentityHashMap<Object, Boolean> visited) {
        long size = 0L;
        for (Object value : collection) size += sizeOf(value, visited);
        return size;
    }

    private static long mapSize(Map<?, ?> map, IdentityHashMap<Object, Boolean> visited) {
        long size = 0L;
        for (Map.Entry<?, ?> entry : map.entrySet()) {
            size += sizeOf(entry.getKey(), visited);
            size += sizeOf(entry.getValue(), visited);
        }
        return size;
    }

    private static boolean shouldSkip(Object target) {
        return target instanceof Curve
//                || target instanceof Random
//                || target instanceof MessageDigest
//                || target instanceof Class
                || target instanceof CH
                || target instanceof IBCH
                || target instanceof PBCH
                || target instanceof ABE
                || target instanceof PKE
                || target instanceof SE
                || target instanceof S
//                || target.getClass().isEnum()
                ;
    }

    private static boolean isLeafType(Class<?> clazz) {
        return clazz.isPrimitive()
                || clazz == String.class
                || clazz == BigInteger.class
                || clazz == BitSet.class
                || Number.class.isAssignableFrom(clazz)
                || clazz == Boolean.class
                || clazz == Character.class
                || (clazz.isArray() && clazz.getComponentType().isPrimitive());
    }
}
