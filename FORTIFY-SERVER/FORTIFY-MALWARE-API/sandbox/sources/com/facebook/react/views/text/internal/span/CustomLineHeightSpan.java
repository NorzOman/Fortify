package com.facebook.react.views.text.internal.span;

import android.graphics.Paint;
import android.text.style.LineHeightSpan;
import com.facebook.react.uimanager.ViewProps;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

/* compiled from: CustomLineHeightSpan.kt */
@Metadata(d1 = {"\u00002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0007\n\u0002\b\u0003\n\u0002\u0010\b\n\u0002\b\u0003\n\u0002\u0010\u0002\n\u0000\n\u0002\u0010\r\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0000\u0018\u00002\u00020\u00012\u00020\u0002B\u000f\u0012\u0006\u0010\u0003\u001a\u00020\u0004¢\u0006\u0004\b\u0005\u0010\u0006J8\u0010\u000b\u001a\u00020\f2\u0006\u0010\r\u001a\u00020\u000e2\u0006\u0010\u000f\u001a\u00020\b2\u0006\u0010\u0010\u001a\u00020\b2\u0006\u0010\u0011\u001a\u00020\b2\u0006\u0010\u0012\u001a\u00020\b2\u0006\u0010\u0013\u001a\u00020\u0014H\u0016R\u0011\u0010\u0007\u001a\u00020\b¢\u0006\b\n\u0000\u001a\u0004\b\t\u0010\n¨\u0006\u0015"}, d2 = {"Lcom/facebook/react/views/text/internal/span/CustomLineHeightSpan;", "Landroid/text/style/LineHeightSpan;", "Lcom/facebook/react/views/text/internal/span/ReactSpan;", "height", "", "<init>", "(F)V", ViewProps.LINE_HEIGHT, "", "getLineHeight", "()I", "chooseHeight", "", "text", "", ViewProps.START, ViewProps.END, "spanstartv", "v", "fm", "Landroid/graphics/Paint$FontMetricsInt;", "ReactAndroid_release"}, k = 1, mv = {2, 0, 0}, xi = 48)
/* loaded from: classes.dex */
public final class CustomLineHeightSpan implements LineHeightSpan, ReactSpan {
    private final int lineHeight;

    public CustomLineHeightSpan(float f) {
        this.lineHeight = (int) Math.ceil(f);
    }

    public final int getLineHeight() {
        return this.lineHeight;
    }

    @Override // android.text.style.LineHeightSpan
    public void chooseHeight(CharSequence text, int start, int end, int spanstartv, int v, Paint.FontMetricsInt fm) {
        Intrinsics.checkNotNullParameter(text, "text");
        Intrinsics.checkNotNullParameter(fm, "fm");
        double d = (this.lineHeight - ((-fm.ascent) + fm.descent)) / 2.0f;
        fm.ascent -= (int) Math.ceil(d);
        fm.descent += (int) Math.floor(d);
        if (start == 0) {
            fm.top = fm.ascent;
        }
        if (end == text.length()) {
            fm.bottom = fm.descent;
        }
    }
}
