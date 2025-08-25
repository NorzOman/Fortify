package androidx.autofill.inline.common;

import android.os.Bundle;

/* loaded from: classes.dex */
public abstract class BundledStyle {
    protected final Bundle mBundle;

    protected abstract String getStyleKey();

    protected BundledStyle(Bundle bundle) {
        this.mBundle = bundle;
    }

    public final Bundle getBundle() {
        return this.mBundle;
    }

    public boolean isValid() {
        Bundle bundle = this.mBundle;
        return bundle != null && bundle.getBoolean(getStyleKey(), false);
    }

    public void assertIsValid() {
        if (!isValid()) {
            throw new IllegalStateException("Invalid style, missing bundle key " + getStyleKey());
        }
    }

    public static abstract class Builder<T extends BundledStyle> {
        protected final Bundle mBundle;

        public abstract T build();

        protected Builder(String str) {
            Bundle bundle = new Bundle();
            this.mBundle = bundle;
            bundle.putBoolean(str, true);
        }
    }
}
