package androidx.autofill.inline;

import android.app.slice.Slice;
import android.os.Bundle;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/* loaded from: classes.dex */
public final class UiVersions {
    public static final String INLINE_UI_VERSION_1 = "androidx.autofill.inline.ui.version:v1";
    private static final Set<String> UI_VERSIONS = new HashSet(Arrays.asList(INLINE_UI_VERSION_1));

    public interface Content {
        Slice getSlice();
    }

    @Retention(RetentionPolicy.SOURCE)
    public @interface InlineUiVersion {
    }

    public interface Style {
        Bundle getBundle();

        String getVersion();
    }

    public static Set<String> getUiVersions() {
        return UI_VERSIONS;
    }

    public static List<String> getVersions(Bundle bundle) {
        return VersionUtils.getSupportedVersions(bundle);
    }

    private UiVersions() {
    }

    public static StylesBuilder newStylesBuilder() {
        return new StylesBuilder();
    }

    public static final class StylesBuilder {
        private final List<Style> mStyles = new ArrayList();

        StylesBuilder() {
        }

        public StylesBuilder addStyle(Style style) {
            if (!VersionUtils.isVersionSupported(style.getVersion())) {
                throw new IllegalArgumentException("Unsupported style version: " + style.getVersion());
            }
            this.mStyles.add(style);
            return this;
        }

        public Bundle build() {
            if (this.mStyles.isEmpty()) {
                throw new IllegalStateException("Please put at least one style in the builder");
            }
            Bundle bundle = new Bundle();
            VersionUtils.writeStylesToBundle(this.mStyles, bundle);
            return bundle;
        }
    }
}
