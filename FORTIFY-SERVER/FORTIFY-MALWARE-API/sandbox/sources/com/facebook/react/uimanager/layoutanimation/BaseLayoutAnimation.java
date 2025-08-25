package com.facebook.react.uimanager.layoutanimation;

import android.view.View;
import android.view.animation.Animation;
import android.view.animation.ScaleAnimation;
import com.facebook.react.uimanager.IllegalViewOperationException;

/* loaded from: classes.dex */
abstract class BaseLayoutAnimation extends AbstractLayoutAnimation {
    abstract boolean isReverse();

    BaseLayoutAnimation() {
    }

    @Override // com.facebook.react.uimanager.layoutanimation.AbstractLayoutAnimation
    boolean isValid() {
        return this.mDurationMs > 0 && this.mAnimatedProperty != null;
    }

    /* renamed from: com.facebook.react.uimanager.layoutanimation.BaseLayoutAnimation$1, reason: invalid class name */
    static /* synthetic */ class AnonymousClass1 {
        static final /* synthetic */ int[] $SwitchMap$com$facebook$react$uimanager$layoutanimation$AnimatedPropertyType;

        static {
            int[] iArr = new int[AnimatedPropertyType.values().length];
            $SwitchMap$com$facebook$react$uimanager$layoutanimation$AnimatedPropertyType = iArr;
            try {
                iArr[AnimatedPropertyType.OPACITY.ordinal()] = 1;
            } catch (NoSuchFieldError unused) {
            }
            try {
                $SwitchMap$com$facebook$react$uimanager$layoutanimation$AnimatedPropertyType[AnimatedPropertyType.SCALE_XY.ordinal()] = 2;
            } catch (NoSuchFieldError unused2) {
            }
            try {
                $SwitchMap$com$facebook$react$uimanager$layoutanimation$AnimatedPropertyType[AnimatedPropertyType.SCALE_X.ordinal()] = 3;
            } catch (NoSuchFieldError unused3) {
            }
            try {
                $SwitchMap$com$facebook$react$uimanager$layoutanimation$AnimatedPropertyType[AnimatedPropertyType.SCALE_Y.ordinal()] = 4;
            } catch (NoSuchFieldError unused4) {
            }
        }
    }

    @Override // com.facebook.react.uimanager.layoutanimation.AbstractLayoutAnimation
    Animation createAnimationImpl(View view, int i, int i2, int i3, int i4) {
        if (this.mAnimatedProperty != null) {
            int i5 = AnonymousClass1.$SwitchMap$com$facebook$react$uimanager$layoutanimation$AnimatedPropertyType[this.mAnimatedProperty.ordinal()];
            if (i5 == 1) {
                return new OpacityAnimation(view, isReverse() ? view.getAlpha() : 0.0f, isReverse() ? 0.0f : view.getAlpha());
            }
            if (i5 == 2) {
                float f = isReverse() ? 1.0f : 0.0f;
                float f2 = isReverse() ? 0.0f : 1.0f;
                return new ScaleAnimation(f, f2, f, f2, 1, 0.5f, 1, 0.5f);
            }
            if (i5 == 3) {
                return new ScaleAnimation(isReverse() ? 1.0f : 0.0f, isReverse() ? 0.0f : 1.0f, 1.0f, 1.0f, 1, 0.5f, 1, 0.0f);
            }
            if (i5 == 4) {
                return new ScaleAnimation(1.0f, 1.0f, isReverse() ? 1.0f : 0.0f, isReverse() ? 0.0f : 1.0f, 1, 0.0f, 1, 0.5f);
            }
            throw new IllegalViewOperationException("Missing animation for property : " + this.mAnimatedProperty);
        }
        throw new IllegalViewOperationException("Missing animated property from animation config");
    }
}
