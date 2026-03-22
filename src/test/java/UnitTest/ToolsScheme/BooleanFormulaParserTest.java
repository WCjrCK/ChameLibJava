package UnitTest.ToolsScheme;

import EllipticCurve.Curve.Config;
import EllipticCurve.Curve.Curve;
import EllipticCurve.Curve.CurveGroup;
import EllipticCurve.Curve.CurveName;
import EllipticCurve.Point.Point;
import EllipticCurve.Point.Scalar;
import Encryption.ABE.utils.BooleanFormulaParser;
import MathStructure.LSSS;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class BooleanFormulaParserTest {
    private static final DummyCurve CURVE = new DummyCurve();

    static Stream<Arguments> validDimensions() {
        return Stream.of(
                Arguments.of(1, 1),
                Arguments.of(4, 1),
                Arguments.of(5, 3),
                Arguments.of(6, 6),
                Arguments.of(8, 4)
        );
    }

    static Stream<Arguments> invalidDimensions() {
        return Stream.of(
                Arguments.of(0, 1),
                Arguments.of(1, 0),
                Arguments.of(2, 3)
        );
    }

    @DisplayName("generated formula should parse to exact n x m matrix")
    @ParameterizedTest(name = "rows {0} cols {1}")
    @MethodSource("validDimensions")
    void generateSatisfiableFormulaProducesExactMatrixShape(int n, int m) {
        BooleanFormulaParser.GeneratedFormula generated = BooleanFormulaParser.generateSatisfiableFormula(n, m);
        LSSS lsss = new LSSS();

        BooleanFormulaParser.parse(lsss, CURVE, generated.formula);

        assertEquals(n, lsss.M.length);
        assertEquals(m, lsss.M[0].length);
        assertEquals(n, lsss.policy.length);
        assertEquals(n, new HashSet<>(Arrays.asList(lsss.policy)).size());
        assertTrue(evaluate(generated.formula, generated.satisfyingAttributes.attrs));
    }

    @DisplayName("impossible matrix dimensions should be rejected")
    @ParameterizedTest(name = "rows {0} cols {1}")
    @MethodSource("invalidDimensions")
    void generateSatisfiableFormulaRejectsImpossibleShape(int n, int m) {
        assertThrows(IllegalArgumentException.class, () -> BooleanFormulaParser.generateSatisfiableFormula(n, m));
    }

    private static boolean evaluate(String formula, Set<String> attrs) {
        return new FormulaEvaluator(formula, attrs).parse();
    }

    private static final class FormulaEvaluator {
        private final String formula;
        private final Set<String> attrs;
        private int pos;

        private FormulaEvaluator(String formula, Set<String> attrs) {
            this.formula = formula;
            this.attrs = attrs;
        }

        private boolean parse() {
            boolean value = parseOr();
            if (pos != formula.length()) throw new IllegalArgumentException("unexpected token at position " + pos);
            return value;
        }

        private boolean parseOr() {
            boolean value = parseAnd();
            while (match('|')) value = value | parseAnd();
            return value;
        }

        private boolean parseAnd() {
            boolean value = parseFactor();
            while (match('&')) value = value & parseFactor();
            return value;
        }

        private boolean parseFactor() {
            if (match('(')) {
                boolean value = parseOr();
                expect(')');
                return value;
            }
            int start = pos;
            while (pos < formula.length() && "&|()".indexOf(formula.charAt(pos)) == -1) ++pos;
            if (start == pos) throw new IllegalArgumentException("empty token at position " + pos);
            return attrs.contains(formula.substring(start, pos));
        }

        private boolean match(char ch) {
            if (pos < formula.length() && formula.charAt(pos) == ch) {
                ++pos;
                return true;
            }
            return false;
        }

        private void expect(char ch) {
            if (!match(ch)) throw new IllegalArgumentException("expected '" + ch + "' at position " + pos);
        }
    }

    private static final class DummyCurve extends Curve<DummyPoint, DummyPoint, DummyPoint, DummyScalar> {
        private DummyCurve() {
            super(new Config(CurveName.SECP256K1));
        }

        @Override
        protected DummyPoint createG1() {
            return new DummyPoint(CurveGroup.G1, BigInteger.ZERO);
        }

        @Override
        protected DummyPoint createG2() {
            return new DummyPoint(CurveGroup.G2, BigInteger.ZERO);
        }

        @Override
        protected DummyPoint createGT() {
            return new DummyPoint(CurveGroup.GT, BigInteger.ONE);
        }

        @Override
        protected DummyScalar createZp() {
            return new DummyScalar(BigInteger.ZERO);
        }

        @Override
        protected DummyPoint getOneG1() {
            return new DummyPoint(CurveGroup.G1, BigInteger.ONE);
        }

        @Override
        protected DummyPoint getOneG2() {
            return new DummyPoint(CurveGroup.G2, BigInteger.ONE);
        }

        @Override
        protected DummyPoint getOneGT() {
            return new DummyPoint(CurveGroup.GT, BigInteger.ONE);
        }

        @Override
        protected DummyScalar getOneZp() {
            return new DummyScalar(BigInteger.ONE);
        }

        @Override
        protected DummyPoint getZeroG1() {
            return new DummyPoint(CurveGroup.G1, BigInteger.ZERO);
        }

        @Override
        protected DummyPoint getZeroG2() {
            return new DummyPoint(CurveGroup.G2, BigInteger.ZERO);
        }

        @Override
        protected DummyPoint getZeroGT() {
            return new DummyPoint(CurveGroup.GT, BigInteger.ZERO);
        }

        @Override
        protected DummyScalar getZeroZp() {
            return new DummyScalar(BigInteger.ZERO);
        }

        @Override
        protected DummyPoint HashToG1Core(byte[] hash) {
            return new DummyPoint(CurveGroup.G1, new BigInteger(1, hash));
        }

        @Override
        protected DummyPoint HashToG2Core(byte[] hash) {
            return new DummyPoint(CurveGroup.G2, new BigInteger(1, hash));
        }

        @Override
        protected DummyPoint HashToGTCore(byte[] hash) {
            return new DummyPoint(CurveGroup.GT, new BigInteger(1, hash));
        }

        @Override
        protected DummyScalar HashToZpCore(byte[] hash) {
            return new DummyScalar(new BigInteger(1, hash));
        }

        @Override
        protected DummyPoint Pairing(DummyPoint p1, DummyPoint p2) {
            return new DummyPoint(CurveGroup.GT, p1.value.multiply(p2.value));
        }

        @Override
        protected DummyPoint createG1FromBytes(byte[] data) {
            return new DummyPoint(CurveGroup.G1, new BigInteger(1, data));
        }

        @Override
        protected DummyPoint createG2FromBytes(byte[] data) {
            return new DummyPoint(CurveGroup.G2, new BigInteger(1, data));
        }

        @Override
        protected DummyPoint createGTFromBytes(byte[] data) {
            return new DummyPoint(CurveGroup.GT, new BigInteger(1, data));
        }

        @Override
        protected DummyScalar createZpFromBytes(byte[] data) {
            return new DummyScalar(new BigInteger(1, data));
        }

        @Override
        protected DummyPoint PowNdonrCore(DummyPoint p) {
            return p.copy();
        }

        @Override
        public DummyScalar createScalarFromString(String s) {
            return new DummyScalar(new BigInteger(s));
        }
    }

    private static final class DummyPoint extends Point<DummyPoint, DummyScalar> {
        private static final BigInteger MOD = BigInteger.valueOf(101);
        private final BigInteger value;

        private DummyPoint(CurveGroup group, BigInteger value) {
            super(CurveName.SECP256K1, group);
            this.value = normalize(value);
        }

        @Override
        protected DummyPoint addCore(DummyPoint other) {
            return new DummyPoint(group, value.add(other.value));
        }

        @Override
        protected DummyPoint subCore(DummyPoint other) {
            return new DummyPoint(group, value.subtract(other.value));
        }

        @Override
        protected DummyPoint mulCore(DummyScalar scalar) {
            return new DummyPoint(group, value.multiply(scalar.value));
        }

        @Override
        protected DummyPoint divCore(DummyScalar scalar) {
            return new DummyPoint(group, value.multiply(scalar.inverseValue()));
        }

        @Override
        protected DummyPoint negCore() {
            return new DummyPoint(group, value.negate());
        }

        @Override
        public BigInteger toBigInteger() {
            return value;
        }

        @Override
        public String toString() {
            return value.toString();
        }

        @Override
        public boolean isEqual(DummyPoint other) {
            return group == other.group && value.equals(other.value);
        }

        @Override
        public DummyPoint copy() {
            return new DummyPoint(group, value);
        }

        @Override
        public byte[] toBytes() {
            return value.toString().getBytes(StandardCharsets.UTF_8);
        }

        private static BigInteger normalize(BigInteger value) {
            return value.mod(MOD);
        }
    }

    private static final class DummyScalar extends Scalar<DummyScalar> {
        private static final BigInteger MOD = BigInteger.valueOf(101);
        private final BigInteger value;

        private DummyScalar(BigInteger value) {
            super(CurveName.SECP256K1);
            this.value = normalize(value);
        }

        @Override
        protected DummyScalar addCore(DummyScalar other) {
            return new DummyScalar(value.add(other.value));
        }

        @Override
        protected DummyScalar subCore(DummyScalar other) {
            return new DummyScalar(value.subtract(other.value));
        }

        @Override
        protected DummyScalar mulCore(DummyScalar scalar) {
            return new DummyScalar(value.multiply(scalar.value));
        }

        @Override
        protected DummyScalar divCore(DummyScalar scalar) {
            return new DummyScalar(value.multiply(scalar.inverseValue()));
        }

        @Override
        protected DummyScalar negCore() {
            return new DummyScalar(value.negate());
        }

        @Override
        public DummyScalar inv() {
            return new DummyScalar(inverseValue());
        }

        @Override
        public String toString() {
            return value.toString();
        }

        @Override
        public DummyScalar copy() {
            return new DummyScalar(value);
        }

        @Override
        public boolean isEqual(DummyScalar other) {
            return value.equals(other.value);
        }

        @Override
        public byte[] toBytes() {
            return value.toString().getBytes(StandardCharsets.UTF_8);
        }

        @Override
        public boolean isOne() {
            return value.equals(BigInteger.ONE);
        }

        @Override
        public boolean isZero() {
            return value.equals(BigInteger.ZERO);
        }

        private BigInteger inverseValue() {
            if (isZero()) throw new ArithmeticException("zero has no inverse");
            return value.modInverse(MOD);
        }

        private static BigInteger normalize(BigInteger value) {
            return value.mod(MOD);
        }
    }
}
