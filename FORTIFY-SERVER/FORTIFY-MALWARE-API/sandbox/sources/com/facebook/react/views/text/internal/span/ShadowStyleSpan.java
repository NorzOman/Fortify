package com.facebook.react.views.text.internal.span;

import android.text.TextPaint;
import android.text.style.CharacterStyle;
import com.facebook.react.uimanager.ViewProps;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

/* compiled from: ShadowStyleSpan.kt */
@Metadata(d1 = {"\u0000*\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0007\n\u0002\b\u0003\n\u0002\u0010\b\n\u0002\b\u0005\n\u0002\u0010\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\u0018\u00002\u00020\u00012\u00020\u0002B'\u0012\u0006\u0010\u0003\u001a\u00020\u0004\u0012\u0006\u0010\u0005\u001a\u00020\u0004\u0012\u0006\u0010\u0006\u001a\u00020\u0004\u0012\u0006\u0010\u0007\u001a\u00020\b¢\u0006\u0004\b\t\u0010\nJ\u0010\u0010\r\u001a\u00020\u000e2\u0006\u0010\u000f\u001a\u00020\u0010H\u0016R\u000e\u0010\u0003\u001a\u00020\u0004X\u0082\u0004¢\u0006\u0002\n\u0000R\u000e\u0010\u0005\u001a\u00020\u0004X\u0082\u0004¢\u0006\u0002\n\u0000R\u000e\u0010\u0006\u001a\u00020\u0004X\u0082\u0004¢\u0006\u0002\n\u0000R\u0011\u0010\u0007\u001a\u00020\b¢\u0006\b\n\u0000\u001a\u0004\b\u000b\u0010\f¨\u0006\u0011"}, d2 = {"Lcom/facebook/react/views/text/internal/span/ShadowStyleSpan;", "Landroid/text/style/CharacterStyle;", "Lcom/facebook/react/views/text/internal/span/ReactSpan;", "dx", "", "dy", "radius", ViewProps.COLOR, "", "<init>", "(FFFI)V", "getColor", "()I", "updateDrawState", "", "textPaint", "Landroid/text/TextPaint;", "ReactAndroid_release"}, k = 1, mv = {2, 0, 0}, xi = 48)
/* loaded from: classes.dex */
public final class ShadowStyleSpan extends CharacterStyle implements ReactSpan {
    private final int color;
    private final float dx;
    private final float dy;
    private final float radius;

    public final int getColor() {
        return this.color;
    }

    public ShadowStyleSpan(float f, float f2, float f3, int i) {
        this.dx = f;
        this.dy = f2;
        this.radius = f3;
        this.color = i;
    }

    @Override // android.text.style.CharacterStyle
    public void updateDrawState(TextPaint textPaint) {
        Intrinsics.checkNotNullParameter(textPaint, "textPaint");
        textPaint.setShadowLayer(this.radius, this.dx, this.dy, this.color);
    }
}
