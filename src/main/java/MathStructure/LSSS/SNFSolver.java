package MathStructure.LSSS;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Set;

public class SNFSolver {
    public static final class SolveResult {
        public final boolean solvable;
        public final int[] x;
        public final int rank;

        private SolveResult(boolean solvable, int[] x, int rank) {
            this.solvable = solvable;
            this.x = x;
            this.rank = rank;
        }

        public static SolveResult noSolution(int variableCount, int rank) {
            return new SolveResult(false, new int[variableCount], rank);
        }

        public static SolveResult solved(int[] x, int rank) {
            return new SolveResult(true, x, rank);
        }
    }

    public static final class PolicySolveResult {
        public final boolean solvable;
        public final int[] fullX;
        public final int[] activeRows;
        public final int rank;

        private PolicySolveResult(boolean solvable, int[] fullX, int[] activeRows, int rank) {
            this.solvable = solvable;
            this.fullX = fullX;
            this.activeRows = activeRows;
            this.rank = rank;
        }
    }

    private static final class SnfWork {
        private final int[][] A;
        private final int[][] U;
        private final int[][] V;
        private final int rowCount;
        private final int colCount;

        private SnfWork(int[][] a) {
            this.A = deepCopy(a);
            this.rowCount = a.length;
            this.colCount = a.length == 0 ? 0 : a[0].length;
            this.U = identity(rowCount);
            this.V = identity(colCount);
        }
    }

    private static final class Pivot {
        private final int row;
        private final int col;

        private Pivot(int row, int col) {
            this.row = row;
            this.col = col;
        }
    }

    private SNFSolver() {}

    public static SolveResult solveAxEqB(int[][] A, int[] b) {
        validateMatrix(A);
        int m = A.length;
        int n = (m == 0) ? 0 : A[0].length;
        if (b.length != m) {
            throw new IllegalArgumentException("b.length must equal A row count");
        }
        if (m == 0) {
            return SolveResult.solved(new int[n], 0);
        }

        SnfWork w = smithNormalForm(A);

        int[] bPrime = mulMatVec(w.U, b);
        int rank = 0;
        int limit = Math.min(w.rowCount, w.colCount);
        while (rank < limit && w.A[rank][rank] != 0) rank++;

        for (int i = rank; i < w.rowCount; i++) {
            if (bPrime[i] != 0) {
                return SolveResult.noSolution(n, rank);
            }
        }

        int[] y = new int[w.colCount];
        for (int i = 0; i < rank; i++) {
            int d = w.A[i][i];
            if (d == 0 || bPrime[i] % d != 0) {
                return SolveResult.noSolution(n, rank);
            }
            y[i] = bPrime[i] / d;
        }

        int[] x = mulMatVec(w.V, y);
        return SolveResult.solved(x, rank);
    }

    public static PolicySolveResult solvePolicyAxEqB(int[][] A, String[] policy, Set<String> attrs, int[] b) {
        validateMatrix(A);
        if (A.length != policy.length) {
            throw new IllegalArgumentException("policy.length must equal A row count");
        }
        if (A.length == 0) {
            return new PolicySolveResult(b.length == 0, new int[0], new int[0], 0);
        }

        List<Integer> active = new ArrayList<>();
        for (int i = 0; i < policy.length; i++) {
            if (attrs.contains(policy[i])) active.add(i);
        }

        int cols = A[0].length;
        if (b.length != cols) {
            throw new IllegalArgumentException("b.length must equal A column count in policy solve");
        }

        int activeCount = active.size();
        int[] activeRows = new int[activeCount];
        int[][] selectedTranspose = new int[cols][activeCount];
        for (int j = 0; j < activeCount; j++) {
            int srcRow = active.get(j);
            activeRows[j] = srcRow;
            for (int k = 0; k < cols; k++) {
                selectedTranspose[k][j] = A[srcRow][k];
            }
        }

        SolveResult partial = solveAxEqB(selectedTranspose, b);
        int[] fullX = new int[A.length];
        if (partial.solvable) {
            for (int i = 0; i < activeRows.length; i++) {
                fullX[activeRows[i]] = partial.x[i];
            }
        }
        return new PolicySolveResult(partial.solvable, fullX, activeRows, partial.rank);
    }

    private static SnfWork smithNormalForm(int[][] A) {
        SnfWork w = new SnfWork(A);
        int k = 0;
        int limit = Math.min(w.rowCount, w.colCount);
        while (k < limit) {
            Pivot pivot = findMinAbsPivot(w.A, k);
            if (pivot == null) break;

            if (pivot.row != k) swapRows(w, pivot.row, k);
            if (pivot.col != k) swapCols(w, pivot.col, k);

            reduceAt(w, k);

            if (w.A[k][k] < 0) {
                scaleRow(w, k, -1);
            }
            k++;
        }
        return w;
    }

    private static Pivot findMinAbsPivot(int[][] a, int start) {
        int r = -1;
        int c = -1;
        int best = Integer.MAX_VALUE;
        for (int i = start; i < a.length; i++) {
            for (int j = start; j < a[i].length; j++) {
                int v = a[i][j];
                if (v == 0) continue;
                int av = Math.abs(v);
                if (av < best) {
                    best = av;
                    r = i;
                    c = j;
                }
            }
        }
        if (r < 0) return null;
        return new Pivot(r, c);
    }

    private static void reduceAt(SnfWork w, int k) {
        if (w.A[k][k] == 0) return;
        boolean changed;
        do {
            changed = false;

            for (int i = 0; i < w.rowCount; i++) {
                if (i == k) continue;
                while (w.A[i][k] != 0) {
                    if (w.A[k][k] == 0 && !promotePivot(w, k)) return;
                    int pivot = w.A[k][k];
                    int q = w.A[i][k] / pivot;
                    addRow(w, i, k, -q);
                    if (w.A[i][k] != 0 && absAsLong(w.A[i][k]) < absAsLong(w.A[k][k])) {
                        swapRows(w, i, k);
                    }
                    changed = true;
                }
            }

            for (int j = 0; j < w.colCount; j++) {
                if (j == k) continue;
                while (w.A[k][j] != 0) {
                    if (w.A[k][k] == 0 && !promotePivot(w, k)) return;
                    int pivot = w.A[k][k];
                    int q = w.A[k][j] / pivot;
                    addCol(w, j, k, -q);
                    if (w.A[k][j] != 0 && absAsLong(w.A[k][j]) < absAsLong(w.A[k][k])) {
                        swapCols(w, j, k);
                    }
                    changed = true;
                }
            }

            if (w.A[k][k] == 0) return;

            for (int i = 0; i < w.rowCount; i++) {
                if (i == k) continue;
                for (int j = 0; j < w.colCount; j++) {
                    if (j == k) continue;
                    int pivot = w.A[k][k];
                    if (w.A[i][j] % pivot != 0) {
                        addRow(w, i, k, 1);
                        changed = true;
                        i = w.rowCount;
                        break;
                    }
                }
            }
        } while (changed);

        for (int i = 0; i < w.rowCount; i++) {
            if (i == k) continue;
            int pivot = w.A[k][k];
            if (pivot == 0) return;
            int q = w.A[i][k] / pivot;
            addRow(w, i, k, -q);
        }

        for (int j = 0; j < w.colCount; j++) {
            if (j == k) continue;
            int pivot = w.A[k][k];
            if (pivot == 0) return;
            int q = w.A[k][j] / pivot;
            addCol(w, j, k, -q);
        }
    }
    private static void validateMatrix(int[][] A) {
        if (A == null) throw new IllegalArgumentException("A is null");
        int cols = A.length == 0 ? 0 : A[0].length;
        for (int i = 1; i < A.length; i++) {
            if (A[i].length != cols) {
                throw new IllegalArgumentException("matrix must be rectangular");
            }
        }
    }

    private static int[][] deepCopy(int[][] src) {
        int[][] out = new int[src.length][];
        for (int i = 0; i < src.length; i++) out[i] = Arrays.copyOf(src[i], src[i].length);
        return out;
    }

    private static int[][] identity(int n) {
        int[][] id = new int[n][n];
        for (int i = 0; i < n; i++) id[i][i] = 1;
        return id;
    }

    private static int[] mulMatVec(int[][] mat, int[] vec) {
        if (mat.length == 0) return new int[0];
        if (mat[0].length != vec.length) {
            throw new IllegalArgumentException("matrix/vector shape mismatch");
        }
        int[] out = new int[mat.length];
        for (int i = 0; i < mat.length; i++) {
            long acc = 0;
            for (int j = 0; j < mat[i].length; j++) {
                acc += (long) mat[i][j] * vec[j];
            }
            out[i] = checkedInt(acc);
        }
        return out;
    }

    private static void swapRows(SnfWork w, int r1, int r2) {
        int[] tmp = w.A[r1];
        w.A[r1] = w.A[r2];
        w.A[r2] = tmp;

        tmp = w.U[r1];
        w.U[r1] = w.U[r2];
        w.U[r2] = tmp;
    }

    private static void swapCols(SnfWork w, int c1, int c2) {
        for (int i = 0; i < w.rowCount; i++) {
            int t = w.A[i][c1];
            w.A[i][c1] = w.A[i][c2];
            w.A[i][c2] = t;
        }
        for (int i = 0; i < w.colCount; i++) {
            int t = w.V[i][c1];
            w.V[i][c1] = w.V[i][c2];
            w.V[i][c2] = t;
        }
    }

    private static void addRow(SnfWork w, int target, int src, int k) {
        for (int j = 0; j < w.colCount; j++) {
            long v = (long) w.A[target][j] + (long) k * w.A[src][j];
            w.A[target][j] = checkedInt(v);
        }
        for (int j = 0; j < w.rowCount; j++) {
            long v = (long) w.U[target][j] + (long) k * w.U[src][j];
            w.U[target][j] = checkedInt(v);
        }
    }

    private static void addCol(SnfWork w, int target, int src, int k) {
        for (int i = 0; i < w.rowCount; i++) {
            long v = (long) w.A[i][target] + (long) k * w.A[i][src];
            w.A[i][target] = checkedInt(v);
        }
        for (int i = 0; i < w.colCount; i++) {
            long v = (long) w.V[i][target] + (long) k * w.V[i][src];
            w.V[i][target] = checkedInt(v);
        }
    }

    private static void scaleRow(SnfWork w, int row, int factor) {
        for (int j = 0; j < w.colCount; j++) {
            long v = (long) w.A[row][j] * factor;
            w.A[row][j] = checkedInt(v);
        }
        for (int j = 0; j < w.rowCount; j++) {
            long v = (long) w.U[row][j] * factor;
            w.U[row][j] = checkedInt(v);
        }
    }

    private static int checkedInt(long value) {
        if (value > Integer.MAX_VALUE || value < Integer.MIN_VALUE) {
            throw new ArithmeticException("int overflow in LSSS SNF solve");
        }
        return (int) value;
    }

    private static long absAsLong(int v) {
        return v == Integer.MIN_VALUE ? (long) Integer.MAX_VALUE + 1L : Math.abs(v);
    }

    private static boolean promotePivot(SnfWork w, int k) {
        if (w.A[k][k] != 0) return true;

        for (int i = k + 1; i < w.rowCount; i++) {
            if (w.A[i][k] != 0) {
                swapRows(w, i, k);
                return true;
            }
        }
        for (int j = k + 1; j < w.colCount; j++) {
            if (w.A[k][j] != 0) {
                swapCols(w, j, k);
                return true;
            }
        }
        for (int i = k + 1; i < w.rowCount; i++) {
            for (int j = k + 1; j < w.colCount; j++) {
                if (w.A[i][j] != 0) {
                    swapRows(w, i, k);
                    swapCols(w, j, k);
                    return true;
                }
            }
        }
        return false;
    }
}
