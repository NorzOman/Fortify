package com.facebook.drawee.view;

import android.view.View;
import android.view.ViewGroup;
import androidx.constraintlayout.solver.widgets.analyzer.BasicMeasure;
import javax.annotation.Nullable;

/* loaded from: classes.dex */
public class AspectRatioMeasure {

    public static class Spec {
        public int height;
        public int width;
    }

    private static boolean shouldAdjust(int i) {
        return i == 0 || i == -2;
    }

    public static void updateMeasureSpec(Spec spec, float f, @Nullable ViewGroup.LayoutParams layoutParams, int i, int i2) {
        if (f <= 0.0f || layoutParams == null) {
            return;
        }
        if (shouldAdjust(layoutParams.height)) {
            spec.height = View.MeasureSpec.makeMeasureSpec(View.resolveSize((int) (((View.MeasureSpec.getSize(spec.width) - i) / f) + i2), spec.height), BasicMeasure.EXACTLY);
        } else if (shouldAdjust(layoutParams.width)) {
            spec.width = View.MeasureSpec.makeMeasureSpec(View.resolveSize((int) (((View.MeasureSpec.getSize(spec.height) - i2) * f) + i), spec.width), BasicMeasure.EXACTLY);
        }
    }
}
