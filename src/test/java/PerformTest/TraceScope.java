package PerformTest;

import java.util.*;

public class TraceScope {
    private static final ThreadLocal<Map<String, Integer>> COUNTER = new ThreadLocal<>();

    private static final Map<String, Integer> key_list = new HashMap<>();

    private static final List<String> key_alias = new ArrayList<>();
    private static final ThreadLocal<int[]> count = new ThreadLocal<>();

    static {
        int i = 0;
        key_alias.add("M_G1");
        key_list.put("Mul in G1", i);
        i++;
        key_alias.add("M_G2");
        key_list.put("Mul in G2", i);
        i++;
        key_alias.add("M_GT");
        key_list.put("Mul in GT", i);
        i++;
        key_alias.add("M_Zp");
        key_list.put("Mul in Zp", i);
        i++;

        key_alias.add("E_G1");
        key_list.put("Pow in G1", i);
        i++;
        key_alias.add("E_G2");
        key_list.put("Pow in G2", i);
        i++;
        key_alias.add("E_GT");
        key_list.put("Pow in GT", i);
        i++;
        key_alias.add("E_Zp");
        key_list.put("Pow in Zp", i);
        i++;

        key_alias.add("P");
        key_list.put("Pairing", i);
        i++;

        key_alias.add("R_G1");
        key_list.put("Random in G1", i);
        i++;
        key_alias.add("R_G2");
        key_list.put("Random in G2", i);
        i++;
        key_alias.add("R_GT");
        key_list.put("Random in GT", i);
        i++;
        key_alias.add("R_Zp");
        key_list.put("Random in Zp", i);
        i++;

        key_alias.add("H_G1");
        key_list.put("Hash to G1", i);
        i++;
        key_alias.add("H_G2");
        key_list.put("Hash to G2", i);
        i++;
        key_alias.add("H_GT");
        key_list.put("Hash to GT", i);
        i++;
        key_alias.add("H_Zp");
        key_list.put("Hash to Zp", i);
    }

    private TraceScope() {}

    public static AutoCloseable begin() {
        COUNTER.set(new LinkedHashMap<>());
        count.set(new int[key_alias.size()]);
        return () -> COUNTER.remove();
    }

    static void hit(String key) {
        if (key_list.containsKey(key)) {
            int[] c = count.get();
            c[key_list.get(key)]++;
        } else {
            Map<String, Integer> m = COUNTER.get();
            if (m != null) m.merge(key, 1, Integer::sum);
        }
    }

    public static String getTitle() {
        StringBuilder res = new StringBuilder("Stage");
        for(String s : key_alias) res.append(", ").append(s);
        return res + "\n";
    }

    public static String getData() {
        StringBuilder res = new StringBuilder();
        int[] c = count.get();
        for(int i = 0;i < key_alias.size();++i) {
            if(c[i] > 0) {
                if(!res.toString().isEmpty()) res.append(" + ");
                if(c[i] > 1) res.append(c[i]);
                res.append(key_alias.get(i));
            }
        }
        return res.toString();
    }

    public static Map<String, Integer> snapshot() {
        Map<String, Integer> m = COUNTER.get();
        return m == null ? Map.of() : new LinkedHashMap<>(m);
    }

    public static boolean active() {
        return COUNTER.get() != null;
    }
}
