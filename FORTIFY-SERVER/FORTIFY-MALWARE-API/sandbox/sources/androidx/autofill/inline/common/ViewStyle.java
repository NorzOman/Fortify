package androidx.autofill.inline.common;

import android.graphics.drawable.Drawable;
import android.graphics.drawable.Icon;
import android.os.Bundle;
import android.view.View;
import android.view.ViewGroup;
import androidx.autofill.inline.common.BundledStyle;
import androidx.core.util.Preconditions;

/* loaded from: classes.dex */
public class ViewStyle extends BundledStyle {
    private static final String KEY_BACKGROUND = "background";
    private static final String KEY_BACKGROUND_COLOR = "background_color";
    private static final String KEY_LAYOUT_MARGIN = "layout_margin";
    private static final String KEY_PADDING = "padding";
    private static final String KEY_VIEW_STYLE = "view_style";

    public ViewStyle(Bundle bundle) {
        super(bundle);
    }

    public void applyStyleOnViewIfValid(View view) {
        int[] intArray;
        int[] intArray2;
        Icon icon;
        Drawable drawableLoadDrawable;
        if (isValid()) {
            if (this.mBundle.containsKey("background") && (icon = (Icon) this.mBundle.getParcelable("background")) != null && (drawableLoadDrawable = icon.loadDrawable(view.getContext())) != null) {
                view.setBackground(drawableLoadDrawable);
            }
            if (this.mBundle.containsKey(KEY_BACKGROUND_COLOR)) {
                view.setBackgroundColor(this.mBundle.getInt(KEY_BACKGROUND_COLOR));
            }
            if (this.mBundle.containsKey("padding") && (intArray2 = this.mBundle.getIntArray("padding")) != null && intArray2.length == 4) {
                if (view.getLayoutDirection() == 0) {
                    view.setPadding(intArray2[0], intArray2[1], intArray2[2], intArray2[3]);
                } else {
                    view.setPadding(intArray2[2], intArray2[1], intArray2[0], intArray2[3]);
                }
            }
            if (this.mBundle.containsKey(KEY_LAYOUT_MARGIN) && (intArray = this.mBundle.getIntArray(KEY_LAYOUT_MARGIN)) != null && intArray.length == 4) {
                ViewGroup.LayoutParams layoutParams = view.getLayoutParams();
                if (layoutParams == null) {
                    layoutParams = new ViewGroup.MarginLayoutParams(-1, -1);
                } else if (!(layoutParams instanceof ViewGroup.MarginLayoutParams)) {
                    layoutParams = new ViewGroup.MarginLayoutParams(layoutParams);
                }
                ViewGroup.MarginLayoutParams marginLayoutParams = (ViewGroup.MarginLayoutParams) layoutParams;
                if (view.getLayoutDirection() == 0) {
                    marginLayoutParams.setMargins(intArray[0], intArray[1], intArray[2], intArray[3]);
                } else {
                    marginLayoutParams.setMargins(intArray[2], intArray[1], intArray[0], intArray[3]);
                }
                view.setLayoutParams(marginLayoutParams);
            }
        }
    }

    @Override // androidx.autofill.inline.common.BundledStyle
    protected String getStyleKey() {
        return KEY_VIEW_STYLE;
    }

    public static abstract class BaseBuilder<T extends ViewStyle, B extends BaseBuilder<T, B>> extends BundledStyle.Builder<T> {
        protected abstract B getThis();

        protected BaseBuilder(String str) {
            super(str);
        }

        public B setBackground(Icon icon) {
            Preconditions.checkNotNull(icon, "background icon should not be null");
            this.mBundle.putParcelable("background", icon);
            return (B) getThis();
        }

        public B setBackgroundColor(int i) {
            this.mBundle.putInt(ViewStyle.KEY_BACKGROUND_COLOR, i);
            return (B) getThis();
        }

        public B setPadding(int i, int i2, int i3, int i4) {
            this.mBundle.putIntArray("padding", new int[]{i, i2, i3, i4});
            return (B) getThis();
        }

        public B setLayoutMargin(int i, int i2, int i3, int i4) {
            this.mBundle.putIntArray(ViewStyle.KEY_LAYOUT_MARGIN, new int[]{i, i2, i3, i4});
            return (B) getThis();
        }
    }

    public static final class Builder extends BaseBuilder<ViewStyle, Builder> {
        /* JADX INFO: Access modifiers changed from: protected */
        @Override // androidx.autofill.inline.common.ViewStyle.BaseBuilder
        public Builder getThis() {
            return this;
        }

        public Builder() {
            super(ViewStyle.KEY_VIEW_STYLE);
        }

        @Override // androidx.autofill.inline.common.BundledStyle.Builder
        public ViewStyle build() {
            return new ViewStyle(this.mBundle);
        }
    }
}
