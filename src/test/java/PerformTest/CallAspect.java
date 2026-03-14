package PerformTest;

import EllipticCurve.Curve.CurveGroup;
import EllipticCurve.Point.Point;
import EllipticCurve.Point.Scalar;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;

@Aspect
public class CallAspect {
    @Around(
            "(" +
                    "execution(* ChameleonHash.*CH..*.Setup(..))" +
                    " || execution(* ChameleonHash.*CH..*.KeyGen(..))" +
                    " || execution(* ChameleonHash.*CH..*.Hash(..))" +
                    " || execution(* ChameleonHash.*CH..*.Verify(..))" +
                    " || execution(* ChameleonHash.*CH..*.Collision(..))" +
            ")" +
            " && !execution(* EllipticCurve..*(..))" +
            " && !within(PerformTest..*)"
    )
    public Object aroundAllCHStage(ProceedingJoinPoint pjp) throws Throwable {
//        System.out.println(pjp.getSignature().toString());
        TraceScope.enter(pjp.getSignature().toString());
        Object ret_val = pjp.proceed();
        TraceScope.exit();
        return ret_val;
    }

    @Around(
            "(" +
                    "execution(* EllipticCurve.Point..*.*Core(..))" +
                    " || execution(* EllipticCurve.Curve..*.createPoint(..))" +
                    " || execution(* EllipticCurve.Curve..*.createScalar(..))" +
                    " || execution(protected * EllipticCurve.Curve..*.Pairing(..))" +
                    " || execution(* EllipticCurve.Curve..*.getRandom*(..))" +
                    " || execution(* ChameleonHash..PublicParam+.H*(..))" +
            ")" +
            " && !execution(* *.toString(..))" +
            " && !execution(* *.hashCode(..))" +
            " && !execution(* *.equals(..))" +
            " && !within(PerformTest..*)"
    )
    public Object countBaseInst(ProceedingJoinPoint pjp) throws Throwable {
        if (!TraceScope.active()) return pjp.proceed();
        Object target = pjp.getTarget();
        Object[] args = pjp.getArgs();
        String method = pjp.getSignature().toString();
        String key = method;
        Object ret_val = pjp.proceed();

        if (method.contains("getRandom")) {
            if (method.contains("getRandomPoint")) {
                if (args[0] instanceof CurveGroup) key = "Random in " + ((CurveGroup) args[0]).name();
            } else if (method.contains("getRandomScalar")) key = "Random in Zp";
        } else if (method.contains("PublicParam.H")) {
            if (ret_val instanceof Point<?, ?>) key = "Hash to " + ((Point<?, ?>) ret_val).group();
            else if (ret_val instanceof Scalar<?>) key = "Hash to Zp";
        } else if (method.contains("Pairing")) key = "Pairing";
        else if (method.contains("addCore") || method.contains("subCore")) {
            if (target instanceof Point<?, ?>) key = "Mul in " + ((Point<?, ?>) target).group();
            else if (ret_val instanceof Scalar<?>) key = "Mul in Zp";
        }
        else if (method.contains("mulCore") || method.contains("divCore")) {
            if (target instanceof Point<?, ?>) key = "Pow in " + ((Point<?, ?>) target).group();
            else if (ret_val instanceof Scalar<?>) key = "Pow in Zp";
        }
        TraceScope.hit(key);
        return ret_val;
    }
}
