package com.facebook.react.views.text.internal.span;

import android.text.TextPaint;
import android.text.style.MetricAffectingSpan;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

/* compiled from: CustomLetterSpacingSpan.kt */
@Metadata(d1 = {"\u0000$\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0007\n\u0002\b\u0005\n\u0002\u0010\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0003\u0018\u00002\u00020\u00012\u00020\u0002B\u000f\u0012\u0006\u0010\u0003\u001a\u00020\u0004¢\u0006\u0004\b\u0005\u0010\u0006J\u0010\u0010\t\u001a\u00020\n2\u0006\u0010\u000b\u001a\u00020\fH\u0016J\u0010\u0010\r\u001a\u00020\n2\u0006\u0010\u000b\u001a\u00020\fH\u0016J\u0010\u0010\u000e\u001a\u00020\n2\u0006\u0010\u000b\u001a\u00020\fH\u0002R\u0011\u0010\u0003\u001a\u00020\u0004¢\u0006\b\n\u0000\u001a\u0004\b\u0007\u0010\b¨\u0006\u000f"}, d2 = {"Lcom/facebook/react/views/text/internal/span/CustomLetterSpacingSpan;", "Landroid/text/style/MetricAffectingSpan;", "Lcom/facebook/react/views/text/internal/span/ReactSpan;", "spacing", "", "<init>", "(F)V", "getSpacing", "()F", "updateDrawState", "", "paint", "Landroid/text/TextPaint;", "updateMeasureState", "apply", "ReactAndroid_release"}, k = 1, mv = {2, 0, 0}, xi = 48)
/* loaded from: classes.dex */
public final class CustomLetterSpacingSpan extends MetricAffectingSpan implements ReactSpan {
    private final float spacing;

    public CustomLetterSpacingSpan(float f) {
        this.spacing = f;
    }

    public final float getSpacing() {
        return this.spacing;
    }

    @Override // android.text.style.CharacterStyle
    public void updateDrawState(TextPaint paint) {
        Intrinsics.checkNotNullParameter(paint, "paint");
        apply(paint);
    }

    @Override // android.text.style.MetricAffectingSpan
    public void updateMeasureState(TextPaint paint) {
        Intrinsics.checkNotNullParameter(paint, "paint");
        apply(paint);
    }

    private final void apply(TextPaint paint) {
        if (Float.isNaN(this.spacing)) {
            return;
        }
        paint.setLetterSpacing(this.spacing);
    }
}
