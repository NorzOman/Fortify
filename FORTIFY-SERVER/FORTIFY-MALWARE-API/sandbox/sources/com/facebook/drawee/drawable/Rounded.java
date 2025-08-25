package com.facebook.drawee.drawable;

import com.facebook.react.uimanager.ViewProps;
import kotlin.Metadata;

/* compiled from: Rounded.kt */
@Metadata(d1 = {"\u0000.\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0000\n\u0002\u0010\u000b\n\u0002\b\u0004\n\u0002\u0010\u0002\n\u0000\n\u0002\u0010\u0007\n\u0000\n\u0002\u0010\u0014\n\u0002\b\u0006\n\u0002\u0010\b\n\u0002\b\u0014\bf\u0018\u00002\u00020\u0001J\u0010\u0010\u0007\u001a\u00020\b2\u0006\u0010\t\u001a\u00020\nH&J\u0018\u0010\u0011\u001a\u00020\b2\u0006\u0010\u0012\u001a\u00020\u00132\u0006\u0010\u0014\u001a\u00020\nH&J\u0010\u0010%\u001a\u00020\b2\u0006\u0010&\u001a\u00020\u0003H&R\u0018\u0010\u0002\u001a\u00020\u0003X¦\u000e¢\u0006\f\u001a\u0004\b\u0002\u0010\u0004\"\u0004\b\u0005\u0010\u0006R\u0018\u0010\u000b\u001a\u00020\fX¦\u000e¢\u0006\f\u001a\u0004\b\r\u0010\u000e\"\u0004\b\u000f\u0010\u0010R\u0012\u0010\u0015\u001a\u00020\u0013X¦\u0004¢\u0006\u0006\u001a\u0004\b\u0016\u0010\u0017R\u0012\u0010\u0018\u001a\u00020\nX¦\u0004¢\u0006\u0006\u001a\u0004\b\u0019\u0010\u001aR\u0018\u0010\u001b\u001a\u00020\nX¦\u000e¢\u0006\f\u001a\u0004\b\u001c\u0010\u001a\"\u0004\b\u001d\u0010\u001eR\u0018\u0010\u001f\u001a\u00020\u0003X¦\u000e¢\u0006\f\u001a\u0004\b \u0010\u0004\"\u0004\b!\u0010\u0006R\u0018\u0010\"\u001a\u00020\u0003X¦\u000e¢\u0006\f\u001a\u0004\b#\u0010\u0004\"\u0004\b$\u0010\u0006¨\u0006'"}, d2 = {"Lcom/facebook/drawee/drawable/Rounded;", "", "isCircle", "", "()Z", "setCircle", "(Z)V", "setRadius", "", "radius", "", "radii", "", "getRadii", "()[F", "setRadii", "([F)V", "setBorder", ViewProps.COLOR, "", "width", ViewProps.BORDER_COLOR, "getBorderColor", "()I", ViewProps.BORDER_WIDTH, "getBorderWidth", "()F", ViewProps.PADDING, "getPadding", "setPadding", "(F)V", "scaleDownInsideBorders", "getScaleDownInsideBorders", "setScaleDownInsideBorders", "paintFilterBitmap", "getPaintFilterBitmap", "setPaintFilterBitmap", "setRepeatEdgePixels", "repeatEdgePixels", "drawee_release"}, k = 1, mv = {2, 0, 0}, xi = 48)
/* loaded from: classes.dex */
public interface Rounded {
    int getBorderColor();

    float getBorderWidth();

    float getPadding();

    boolean getPaintFilterBitmap();

    float[] getRadii();

    boolean getScaleDownInsideBorders();

    boolean isCircle();

    void setBorder(int color, float width);

    void setCircle(boolean z);

    void setPadding(float f);

    void setPaintFilterBitmap(boolean z);

    void setRadii(float[] fArr);

    void setRadius(float radius);

    void setRepeatEdgePixels(boolean repeatEdgePixels);

    void setScaleDownInsideBorders(boolean z);
}
