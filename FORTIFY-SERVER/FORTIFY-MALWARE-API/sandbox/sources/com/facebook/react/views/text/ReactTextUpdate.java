package com.facebook.react.views.text;

import android.text.Spannable;
import com.facebook.react.uimanager.ViewProps;
import kotlin.Deprecated;
import kotlin.Metadata;
import kotlin.ReplaceWith;
import kotlin.jvm.JvmStatic;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;

/* compiled from: ReactTextUpdate.kt */
@Metadata(d1 = {"\u0000$\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\b\n\u0000\n\u0002\u0010\u000b\n\u0000\n\u0002\u0010\u0007\n\u0002\b\u001c\u0018\u0000 $2\u00020\u0001:\u0001$BW\u0012\u0006\u0010\u0002\u001a\u00020\u0003\u0012\u0006\u0010\u0004\u001a\u00020\u0005\u0012\u0006\u0010\u0006\u001a\u00020\u0007\u0012\u0006\u0010\b\u001a\u00020\t\u0012\u0006\u0010\n\u001a\u00020\t\u0012\u0006\u0010\u000b\u001a\u00020\t\u0012\u0006\u0010\f\u001a\u00020\t\u0012\u0006\u0010\r\u001a\u00020\u0005\u0012\u0006\u0010\u000e\u001a\u00020\u0005\u0012\u0006\u0010\u000f\u001a\u00020\u0005¢\u0006\u0004\b\u0010\u0010\u0011BI\b\u0016\u0012\u0006\u0010\u0002\u001a\u00020\u0003\u0012\u0006\u0010\u0004\u001a\u00020\u0005\u0012\u0006\u0010\u0006\u001a\u00020\u0007\u0012\u0006\u0010\u0012\u001a\u00020\t\u0012\u0006\u0010\n\u001a\u00020\t\u0012\u0006\u0010\u0013\u001a\u00020\t\u0012\u0006\u0010\f\u001a\u00020\t\u0012\u0006\u0010\r\u001a\u00020\u0005¢\u0006\u0004\b\u0010\u0010\u0014B9\b\u0016\u0012\u0006\u0010\u0002\u001a\u00020\u0003\u0012\u0006\u0010\u0004\u001a\u00020\u0005\u0012\u0006\u0010\u0006\u001a\u00020\u0007\u0012\u0006\u0010\r\u001a\u00020\u0005\u0012\u0006\u0010\u000e\u001a\u00020\u0005\u0012\u0006\u0010\u000f\u001a\u00020\u0005¢\u0006\u0004\b\u0010\u0010\u0015J\b\u0010\u0006\u001a\u00020\u0007H\u0007R\u0011\u0010\u0002\u001a\u00020\u0003¢\u0006\b\n\u0000\u001a\u0004\b\u0016\u0010\u0017R\u0011\u0010\u0004\u001a\u00020\u0005¢\u0006\b\n\u0000\u001a\u0004\b\u0018\u0010\u0019R\u0011\u0010\u0006\u001a\u00020\u0007¢\u0006\b\n\u0000\u001a\u0004\b\u001a\u0010\u001bR\u0011\u0010\b\u001a\u00020\t¢\u0006\b\n\u0000\u001a\u0004\b\u001c\u0010\u001dR\u0011\u0010\n\u001a\u00020\t¢\u0006\b\n\u0000\u001a\u0004\b\u001e\u0010\u001dR\u0011\u0010\u000b\u001a\u00020\t¢\u0006\b\n\u0000\u001a\u0004\b\u001f\u0010\u001dR\u0011\u0010\f\u001a\u00020\t¢\u0006\b\n\u0000\u001a\u0004\b \u0010\u001dR\u0011\u0010\r\u001a\u00020\u0005¢\u0006\b\n\u0000\u001a\u0004\b!\u0010\u0019R\u0011\u0010\u000e\u001a\u00020\u0005¢\u0006\b\n\u0000\u001a\u0004\b\"\u0010\u0019R\u0011\u0010\u000f\u001a\u00020\u0005¢\u0006\b\n\u0000\u001a\u0004\b#\u0010\u0019¨\u0006%"}, d2 = {"Lcom/facebook/react/views/text/ReactTextUpdate;", "", "text", "Landroid/text/Spannable;", "jsEventCounter", "", "containsImages", "", ViewProps.PADDING_LEFT, "", ViewProps.PADDING_TOP, ViewProps.PADDING_RIGHT, ViewProps.PADDING_BOTTOM, ViewProps.TEXT_ALIGN, ViewProps.TEXT_BREAK_STRATEGY, "justificationMode", "<init>", "(Landroid/text/Spannable;IZFFFFIII)V", ViewProps.PADDING_START, ViewProps.PADDING_END, "(Landroid/text/Spannable;IZFFFFI)V", "(Landroid/text/Spannable;IZIII)V", "getText", "()Landroid/text/Spannable;", "getJsEventCounter", "()I", "getContainsImages", "()Z", "getPaddingLeft", "()F", "getPaddingTop", "getPaddingRight", "getPaddingBottom", "getTextAlign", "getTextBreakStrategy", "getJustificationMode", "Companion", "ReactAndroid_release"}, k = 1, mv = {2, 0, 0}, xi = 48)
/* loaded from: classes.dex */
public final class ReactTextUpdate {

    /* renamed from: Companion, reason: from kotlin metadata */
    public static final Companion INSTANCE = new Companion(null);
    private final boolean containsImages;
    private final int jsEventCounter;
    private final int justificationMode;
    private final float paddingBottom;
    private final float paddingLeft;
    private final float paddingRight;
    private final float paddingTop;
    private final Spannable text;
    private final int textAlign;
    private final int textBreakStrategy;

    @JvmStatic
    public static final ReactTextUpdate buildReactTextUpdateFromState(Spannable spannable, int i, int i2, int i3, int i4) {
        return INSTANCE.buildReactTextUpdateFromState(spannable, i, i2, i3, i4);
    }

    public ReactTextUpdate(Spannable text, int i, boolean z, float f, float f2, float f3, float f4, int i2, int i3, int i4) {
        Intrinsics.checkNotNullParameter(text, "text");
        this.text = text;
        this.jsEventCounter = i;
        this.containsImages = z;
        this.paddingLeft = f;
        this.paddingTop = f2;
        this.paddingRight = f3;
        this.paddingBottom = f4;
        this.textAlign = i2;
        this.textBreakStrategy = i3;
        this.justificationMode = i4;
    }

    public final Spannable getText() {
        return this.text;
    }

    public final int getJsEventCounter() {
        return this.jsEventCounter;
    }

    public final boolean getContainsImages() {
        return this.containsImages;
    }

    public final float getPaddingLeft() {
        return this.paddingLeft;
    }

    public final float getPaddingTop() {
        return this.paddingTop;
    }

    public final float getPaddingRight() {
        return this.paddingRight;
    }

    public final float getPaddingBottom() {
        return this.paddingBottom;
    }

    public final int getTextAlign() {
        return this.textAlign;
    }

    public final int getTextBreakStrategy() {
        return this.textBreakStrategy;
    }

    public final int getJustificationMode() {
        return this.justificationMode;
    }

    /* JADX WARN: 'this' call moved to the top of the method (can break code semantics) */
    public ReactTextUpdate(Spannable text, int i, boolean z, float f, float f2, float f3, float f4, int i2) {
        this(text, i, z, f, f2, f3, f4, i2, 1, 0);
        Intrinsics.checkNotNullParameter(text, "text");
    }

    /* JADX WARN: 'this' call moved to the top of the method (can break code semantics) */
    public ReactTextUpdate(Spannable text, int i, boolean z, int i2, int i3, int i4) {
        this(text, i, z, -1.0f, -1.0f, -1.0f, -1.0f, i2, i3, i4);
        Intrinsics.checkNotNullParameter(text, "text");
    }

    @Deprecated(message = "This is just for backwards compatibility and will be removed some time in the future", replaceWith = @ReplaceWith(expression = "containsImages", imports = {}))
    /* renamed from: containsImages, reason: from getter */
    public final boolean getContainsImages() {
        return this.containsImages;
    }

    /* compiled from: ReactTextUpdate.kt */
    @Metadata(d1 = {"\u0000 \n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\b\n\u0002\b\u0004\b\u0086\u0003\u0018\u00002\u00020\u0001B\t\b\u0002¢\u0006\u0004\b\u0002\u0010\u0003J0\u0010\u0004\u001a\u00020\u00052\u0006\u0010\u0006\u001a\u00020\u00072\u0006\u0010\b\u001a\u00020\t2\u0006\u0010\n\u001a\u00020\t2\u0006\u0010\u000b\u001a\u00020\t2\u0006\u0010\f\u001a\u00020\tH\u0007¨\u0006\r"}, d2 = {"Lcom/facebook/react/views/text/ReactTextUpdate$Companion;", "", "<init>", "()V", "buildReactTextUpdateFromState", "Lcom/facebook/react/views/text/ReactTextUpdate;", "text", "Landroid/text/Spannable;", "jsEventCounter", "", ViewProps.TEXT_ALIGN, ViewProps.TEXT_BREAK_STRATEGY, "justificationMode", "ReactAndroid_release"}, k = 1, mv = {2, 0, 0}, xi = 48)
    public static final class Companion {
        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        private Companion() {
        }

        @JvmStatic
        public final ReactTextUpdate buildReactTextUpdateFromState(Spannable text, int jsEventCounter, int textAlign, int textBreakStrategy, int justificationMode) {
            Intrinsics.checkNotNullParameter(text, "text");
            return new ReactTextUpdate(text, jsEventCounter, false, textAlign, textBreakStrategy, justificationMode);
        }
    }
}
