package com.facebook.react.views.text.internal.span;

import android.text.TextPaint;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

/* compiled from: ReactTextPaintHolderSpan.kt */
@Metadata(d1 = {"\u0000*\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0007\n\u0002\u0010\u000b\n\u0000\n\u0002\u0010\u0000\n\u0000\n\u0002\u0010\b\n\u0000\n\u0002\u0010\u000e\n\u0000\b\u0086\b\u0018\u00002\u00020\u0001B\u000f\u0012\u0006\u0010\u0002\u001a\u00020\u0003¢\u0006\u0004\b\u0004\u0010\u0005J\t\u0010\b\u001a\u00020\u0003HÆ\u0003J\u0013\u0010\t\u001a\u00020\u00002\b\b\u0002\u0010\u0002\u001a\u00020\u0003HÆ\u0001J\u0013\u0010\n\u001a\u00020\u000b2\b\u0010\f\u001a\u0004\u0018\u00010\rHÖ\u0003J\t\u0010\u000e\u001a\u00020\u000fHÖ\u0001J\t\u0010\u0010\u001a\u00020\u0011HÖ\u0001R\u0011\u0010\u0002\u001a\u00020\u0003¢\u0006\b\n\u0000\u001a\u0004\b\u0006\u0010\u0007¨\u0006\u0012"}, d2 = {"Lcom/facebook/react/views/text/internal/span/ReactTextPaintHolderSpan;", "Lcom/facebook/react/views/text/internal/span/ReactSpan;", "textPaint", "Landroid/text/TextPaint;", "<init>", "(Landroid/text/TextPaint;)V", "getTextPaint", "()Landroid/text/TextPaint;", "component1", "copy", "equals", "", "other", "", "hashCode", "", "toString", "", "ReactAndroid_release"}, k = 1, mv = {2, 0, 0}, xi = 48)
/* loaded from: classes.dex */
public final /* data */ class ReactTextPaintHolderSpan implements ReactSpan {
    private final TextPaint textPaint;

    public static /* synthetic */ ReactTextPaintHolderSpan copy$default(ReactTextPaintHolderSpan reactTextPaintHolderSpan, TextPaint textPaint, int i, Object obj) {
        if ((i & 1) != 0) {
            textPaint = reactTextPaintHolderSpan.textPaint;
        }
        return reactTextPaintHolderSpan.copy(textPaint);
    }

    /* renamed from: component1, reason: from getter */
    public final TextPaint getTextPaint() {
        return this.textPaint;
    }

    public final ReactTextPaintHolderSpan copy(TextPaint textPaint) {
        Intrinsics.checkNotNullParameter(textPaint, "textPaint");
        return new ReactTextPaintHolderSpan(textPaint);
    }

    public boolean equals(Object other) {
        if (this == other) {
            return true;
        }
        return (other instanceof ReactTextPaintHolderSpan) && Intrinsics.areEqual(this.textPaint, ((ReactTextPaintHolderSpan) other).textPaint);
    }

    public int hashCode() {
        return this.textPaint.hashCode();
    }

    public String toString() {
        return "ReactTextPaintHolderSpan(textPaint=" + this.textPaint + ")";
    }

    public ReactTextPaintHolderSpan(TextPaint textPaint) {
        Intrinsics.checkNotNullParameter(textPaint, "textPaint");
        this.textPaint = textPaint;
    }

    public final TextPaint getTextPaint() {
        return this.textPaint;
    }
}
