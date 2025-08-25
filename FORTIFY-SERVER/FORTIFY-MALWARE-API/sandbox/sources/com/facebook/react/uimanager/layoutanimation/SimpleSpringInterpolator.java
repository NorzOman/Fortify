package com.facebook.react.uimanager.layoutanimation;

import android.view.animation.Interpolator;
import com.facebook.react.bridge.ReadableMap;
import com.facebook.react.bridge.ReadableType;
import kotlin.Metadata;
import kotlin.jvm.JvmStatic;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;

/* compiled from: SimpleSpringInterpolator.kt */
@Metadata(d1 = {"\u0000\u0012\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0007\n\u0002\b\u0007\b\u0000\u0018\u0000 \t2\u00020\u0001:\u0001\tB\u0013\b\u0017\u0012\b\b\u0002\u0010\u0002\u001a\u00020\u0003¢\u0006\u0004\b\u0004\u0010\u0005J\u0010\u0010\u0007\u001a\u00020\u00032\u0006\u0010\b\u001a\u00020\u0003H\u0016R\u000e\u0010\u0006\u001a\u00020\u0003X\u0082\u0004¢\u0006\u0002\n\u0000¨\u0006\n"}, d2 = {"Lcom/facebook/react/uimanager/layoutanimation/SimpleSpringInterpolator;", "Landroid/view/animation/Interpolator;", SimpleSpringInterpolator.PARAM_SPRING_DAMPING, "", "<init>", "(F)V", "_springDamping", "getInterpolation", "input", "Companion", "ReactAndroid_release"}, k = 1, mv = {2, 0, 0}, xi = 48)
/* loaded from: classes.dex */
public final class SimpleSpringInterpolator implements Interpolator {

    /* renamed from: Companion, reason: from kotlin metadata */
    public static final Companion INSTANCE = new Companion(null);
    private static final float FACTOR = 0.5f;
    public static final String PARAM_SPRING_DAMPING = "springDamping";
    private final float _springDamping;

    public SimpleSpringInterpolator() {
        this(0.0f, 1, null);
    }

    @JvmStatic
    public static final float getSpringDamping(ReadableMap readableMap) {
        return INSTANCE.getSpringDamping(readableMap);
    }

    public /* synthetic */ SimpleSpringInterpolator(float f, int i, DefaultConstructorMarker defaultConstructorMarker) {
        this((i & 1) != 0 ? 0.5f : f);
    }

    public SimpleSpringInterpolator(float f) {
        this._springDamping = f;
    }

    @Override // android.animation.TimeInterpolator
    public float getInterpolation(float input) {
        return (float) (1 + (Math.pow(2.0d, (-10) * input) * Math.sin((((input - (r4 / 4)) * 3.141592653589793d) * 2) / this._springDamping)));
    }

    /* compiled from: SimpleSpringInterpolator.kt */
    @Metadata(d1 = {"\u0000 \n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\b\u0003\n\u0002\u0010\u0007\n\u0000\n\u0002\u0010\u000e\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0000\b\u0086\u0003\u0018\u00002\u00020\u0001B\t\b\u0002¢\u0006\u0004\b\u0002\u0010\u0003J\u0010\u0010\b\u001a\u00020\u00052\u0006\u0010\t\u001a\u00020\nH\u0007R\u000e\u0010\u0004\u001a\u00020\u0005X\u0082T¢\u0006\u0002\n\u0000R\u000e\u0010\u0006\u001a\u00020\u0007X\u0086T¢\u0006\u0002\n\u0000¨\u0006\u000b"}, d2 = {"Lcom/facebook/react/uimanager/layoutanimation/SimpleSpringInterpolator$Companion;", "", "<init>", "()V", "FACTOR", "", "PARAM_SPRING_DAMPING", "", "getSpringDamping", "params", "Lcom/facebook/react/bridge/ReadableMap;", "ReactAndroid_release"}, k = 1, mv = {2, 0, 0}, xi = 48)
    public static final class Companion {
        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        private Companion() {
        }

        @JvmStatic
        public final float getSpringDamping(ReadableMap params) {
            Intrinsics.checkNotNullParameter(params, "params");
            if (params.getType(SimpleSpringInterpolator.PARAM_SPRING_DAMPING) == ReadableType.Number) {
                return (float) params.getDouble(SimpleSpringInterpolator.PARAM_SPRING_DAMPING);
            }
            return 0.5f;
        }
    }
}
