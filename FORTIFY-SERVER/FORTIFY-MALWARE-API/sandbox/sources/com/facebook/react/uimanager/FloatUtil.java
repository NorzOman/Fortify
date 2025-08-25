package com.facebook.react.uimanager;

import kotlin.Metadata;
import kotlin.jvm.JvmStatic;

/* compiled from: FloatUtil.kt */
@Metadata(d1 = {"\u0000\u001a\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\b\u0003\n\u0002\u0010\u0007\n\u0000\n\u0002\u0010\u000b\n\u0002\b\u0004\bÆ\u0002\u0018\u00002\u00020\u0001B\t\b\u0002¢\u0006\u0004\b\u0002\u0010\u0003J\u0018\u0010\u0006\u001a\u00020\u00072\u0006\u0010\b\u001a\u00020\u00052\u0006\u0010\t\u001a\u00020\u0005H\u0007J!\u0010\u0006\u001a\u00020\u00072\b\u0010\b\u001a\u0004\u0018\u00010\u00052\b\u0010\t\u001a\u0004\u0018\u00010\u0005H\u0007¢\u0006\u0002\u0010\nR\u000e\u0010\u0004\u001a\u00020\u0005X\u0082T¢\u0006\u0002\n\u0000¨\u0006\u000b"}, d2 = {"Lcom/facebook/react/uimanager/FloatUtil;", "", "<init>", "()V", "EPSILON", "", "floatsEqual", "", "f1", "f2", "(Ljava/lang/Float;Ljava/lang/Float;)Z", "ReactAndroid_release"}, k = 1, mv = {2, 0, 0}, xi = 48)
/* loaded from: classes.dex */
public final class FloatUtil {
    private static final float EPSILON = 1.0E-5f;
    public static final FloatUtil INSTANCE = new FloatUtil();

    private FloatUtil() {
    }

    @JvmStatic
    public static final boolean floatsEqual(float f1, float f2) {
        if (Float.isNaN(f1) || Float.isNaN(f2)) {
            if (Float.isNaN(f1) && Float.isNaN(f2)) {
                return true;
            }
        } else if (Math.abs(f2 - f1) < EPSILON) {
            return true;
        }
        return false;
    }

    @JvmStatic
    public static final boolean floatsEqual(Float f1, Float f2) {
        if (f1 == null) {
            return f2 == null;
        }
        if (f2 == null) {
            return false;
        }
        return floatsEqual(f1.floatValue(), f2.floatValue());
    }
}
