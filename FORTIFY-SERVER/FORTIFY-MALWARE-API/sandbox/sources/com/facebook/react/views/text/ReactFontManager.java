package com.facebook.react.views.text;

import android.content.Context;
import android.content.res.AssetManager;
import android.graphics.Typeface;
import com.facebook.react.uimanager.ViewProps;
import kotlin.Deprecated;
import kotlin.Metadata;
import kotlin.jvm.JvmStatic;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;

/* compiled from: ReactFontManager.kt */
@Deprecated(message = "This class is deprecated and will be deleted in the near future. Please use [com.facebook.react.common.assets.ReactFontManager] instead.")
@Metadata(d1 = {"\u0000@\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u000e\n\u0000\n\u0002\u0010\b\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010\u000b\n\u0000\n\u0002\u0010\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0007\b\u0007\u0018\u0000 \u001a2\u00020\u0001:\u0001\u001aB\u0011\b\u0002\u0012\u0006\u0010\u0002\u001a\u00020\u0003¢\u0006\u0004\b\u0004\u0010\u0005J\u001e\u0010\u0006\u001a\u00020\u00072\u0006\u0010\b\u001a\u00020\t2\u0006\u0010\n\u001a\u00020\u000b2\u0006\u0010\f\u001a\u00020\rJ&\u0010\u0006\u001a\u00020\u00072\u0006\u0010\b\u001a\u00020\t2\u0006\u0010\u000e\u001a\u00020\u000b2\u0006\u0010\u000f\u001a\u00020\u00102\u0006\u0010\f\u001a\u00020\rJ&\u0010\u0006\u001a\u00020\u00072\u0006\u0010\b\u001a\u00020\t2\u0006\u0010\n\u001a\u00020\u000b2\u0006\u0010\u000e\u001a\u00020\u000b2\u0006\u0010\f\u001a\u00020\rJ\u001e\u0010\u0011\u001a\u00020\u00122\u0006\u0010\u0013\u001a\u00020\u00142\u0006\u0010\u0015\u001a\u00020\t2\u0006\u0010\u0016\u001a\u00020\u000bJ\u0018\u0010\u0011\u001a\u00020\u00122\u0006\u0010\u0015\u001a\u00020\t2\b\u0010\u0017\u001a\u0004\u0018\u00010\u0007J\u001e\u0010\u0018\u001a\u00020\u00122\u0006\u0010\b\u001a\u00020\t2\u0006\u0010\n\u001a\u00020\u000b2\u0006\u0010\u0019\u001a\u00020\u0007R\u000e\u0010\u0002\u001a\u00020\u0003X\u0082\u0004¢\u0006\u0002\n\u0000¨\u0006\u001b"}, d2 = {"Lcom/facebook/react/views/text/ReactFontManager;", "", "delegate", "Lcom/facebook/react/common/assets/ReactFontManager;", "<init>", "(Lcom/facebook/react/common/assets/ReactFontManager;)V", "getTypeface", "Landroid/graphics/Typeface;", "fontFamilyName", "", "style", "", "assetManager", "Landroid/content/res/AssetManager;", "weight", "italic", "", "addCustomFont", "", "context", "Landroid/content/Context;", ViewProps.FONT_FAMILY, "fontId", "font", "setTypeface", "typeface", "Companion", "ReactAndroid_release"}, k = 1, mv = {2, 0, 0}, xi = 48)
/* loaded from: classes.dex */
public final class ReactFontManager {

    /* renamed from: Companion, reason: from kotlin metadata */
    public static final Companion INSTANCE = new Companion(null);
    private static ReactFontManager instance;
    private final com.facebook.react.common.assets.ReactFontManager delegate;

    public /* synthetic */ ReactFontManager(com.facebook.react.common.assets.ReactFontManager reactFontManager, DefaultConstructorMarker defaultConstructorMarker) {
        this(reactFontManager);
    }

    @JvmStatic
    public static final ReactFontManager getInstance() {
        return INSTANCE.getInstance();
    }

    private ReactFontManager(com.facebook.react.common.assets.ReactFontManager reactFontManager) {
        this.delegate = reactFontManager;
    }

    public final Typeface getTypeface(String fontFamilyName, int style, AssetManager assetManager) {
        Intrinsics.checkNotNullParameter(fontFamilyName, "fontFamilyName");
        Intrinsics.checkNotNullParameter(assetManager, "assetManager");
        return this.delegate.getTypeface(fontFamilyName, style, assetManager);
    }

    public final Typeface getTypeface(String fontFamilyName, int weight, boolean italic, AssetManager assetManager) {
        Intrinsics.checkNotNullParameter(fontFamilyName, "fontFamilyName");
        Intrinsics.checkNotNullParameter(assetManager, "assetManager");
        return this.delegate.getTypeface(fontFamilyName, weight, italic, assetManager);
    }

    public final Typeface getTypeface(String fontFamilyName, int style, int weight, AssetManager assetManager) {
        Intrinsics.checkNotNullParameter(fontFamilyName, "fontFamilyName");
        Intrinsics.checkNotNullParameter(assetManager, "assetManager");
        return this.delegate.getTypeface(fontFamilyName, style, weight, assetManager);
    }

    public final void addCustomFont(Context context, String fontFamily, int fontId) {
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(fontFamily, "fontFamily");
        this.delegate.addCustomFont(context, fontFamily, fontId);
    }

    public final void addCustomFont(String fontFamily, Typeface font) {
        Intrinsics.checkNotNullParameter(fontFamily, "fontFamily");
        this.delegate.addCustomFont(fontFamily, font);
    }

    public final void setTypeface(String fontFamilyName, int style, Typeface typeface) {
        Intrinsics.checkNotNullParameter(fontFamilyName, "fontFamilyName");
        Intrinsics.checkNotNullParameter(typeface, "typeface");
        this.delegate.setTypeface(fontFamilyName, style, typeface);
    }

    /* compiled from: ReactFontManager.kt */
    @Metadata(d1 = {"\u0000\u0014\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\u0002\b\u0086\u0003\u0018\u00002\u00020\u0001B\t\b\u0002¢\u0006\u0004\b\u0002\u0010\u0003J\b\u0010\u0006\u001a\u00020\u0005H\u0007R\u0010\u0010\u0004\u001a\u0004\u0018\u00010\u0005X\u0082\u000e¢\u0006\u0002\n\u0000¨\u0006\u0007"}, d2 = {"Lcom/facebook/react/views/text/ReactFontManager$Companion;", "", "<init>", "()V", "instance", "Lcom/facebook/react/views/text/ReactFontManager;", "getInstance", "ReactAndroid_release"}, k = 1, mv = {2, 0, 0}, xi = 48)
    public static final class Companion {
        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        private Companion() {
        }

        @JvmStatic
        public final ReactFontManager getInstance() {
            ReactFontManager reactFontManager = ReactFontManager.instance;
            if (reactFontManager != null) {
                return reactFontManager;
            }
            ReactFontManager reactFontManager2 = new ReactFontManager(com.facebook.react.common.assets.ReactFontManager.INSTANCE.getInstance(), null);
            Companion companion = ReactFontManager.INSTANCE;
            ReactFontManager.instance = reactFontManager2;
            return reactFontManager2;
        }
    }
}
