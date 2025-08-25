package com.facebook.react.uimanager;

import android.view.View;
import kotlin.Metadata;
import kotlin.jvm.JvmStatic;

/* compiled from: MeasureSpecAssertions.kt */
@Metadata(d1 = {"\u0000\u001a\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\b\u0003\n\u0002\u0010\u0002\n\u0000\n\u0002\u0010\b\n\u0002\b\u0002\bÆ\u0002\u0018\u00002\u00020\u0001B\t\b\u0002¢\u0006\u0004\b\u0002\u0010\u0003J\u0018\u0010\u0004\u001a\u00020\u00052\u0006\u0010\u0006\u001a\u00020\u00072\u0006\u0010\b\u001a\u00020\u0007H\u0007¨\u0006\t"}, d2 = {"Lcom/facebook/react/uimanager/MeasureSpecAssertions;", "", "<init>", "()V", "assertExplicitMeasureSpec", "", "widthMeasureSpec", "", "heightMeasureSpec", "ReactAndroid_release"}, k = 1, mv = {2, 0, 0}, xi = 48)
/* loaded from: classes.dex */
public final class MeasureSpecAssertions {
    public static final MeasureSpecAssertions INSTANCE = new MeasureSpecAssertions();

    private MeasureSpecAssertions() {
    }

    @JvmStatic
    public static final void assertExplicitMeasureSpec(int widthMeasureSpec, int heightMeasureSpec) {
        int mode = View.MeasureSpec.getMode(widthMeasureSpec);
        int mode2 = View.MeasureSpec.getMode(heightMeasureSpec);
        if (mode == 0 || mode2 == 0) {
            throw new IllegalStateException("A catalyst view must have an explicit width and height given to it. This should normally happen as part of the standard catalyst UI framework.");
        }
    }
}
