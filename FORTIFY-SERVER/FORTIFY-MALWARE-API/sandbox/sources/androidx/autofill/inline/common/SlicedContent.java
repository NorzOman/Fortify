package androidx.autofill.inline.common;

import android.app.PendingIntent;
import android.app.slice.Slice;
import android.app.slice.SliceSpec;
import android.net.Uri;
import androidx.autofill.inline.UiVersions;

/* loaded from: classes.dex */
public abstract class SlicedContent implements UiVersions.Content {
    static final Uri INLINE_SLICE_URI = Uri.parse("inline.slice");
    protected final Slice mSlice;

    public abstract PendingIntent getAttributionIntent();

    public abstract boolean isValid();

    protected SlicedContent(Slice slice) {
        this.mSlice = slice;
    }

    @Override // androidx.autofill.inline.UiVersions.Content
    public final Slice getSlice() {
        return this.mSlice;
    }

    public static String getVersion(Slice slice) {
        return slice.getSpec().getType();
    }

    public static abstract class Builder<T extends SlicedContent> {
        protected final Slice.Builder mSliceBuilder;

        public abstract T build();

        protected Builder(String str) {
            this.mSliceBuilder = new Slice.Builder(SlicedContent.INLINE_SLICE_URI, new SliceSpec(str, 1));
        }
    }
}
