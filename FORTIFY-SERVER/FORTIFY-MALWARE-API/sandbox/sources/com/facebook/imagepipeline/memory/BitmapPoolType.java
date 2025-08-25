package com.facebook.imagepipeline.memory;

import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import kotlin.Metadata;

/* compiled from: BitmapPoolType.kt */
@Retention(RetentionPolicy.RUNTIME)
@Metadata(d1 = {"\u0000\f\n\u0002\u0018\u0002\n\u0002\u0010\u001b\n\u0002\b\u0002\b\u0086\u0002\u0018\u0000 \u00022\u00020\u0001:\u0001\u0002B\u0000¨\u0006\u0003"}, d2 = {"Lcom/facebook/imagepipeline/memory/BitmapPoolType;", "", "Companion", "imagepipeline_release"}, k = 1, mv = {2, 0, 0}, xi = 48)
/* loaded from: classes.dex */
public @interface BitmapPoolType {

    /* renamed from: Companion, reason: from kotlin metadata */
    public static final Companion INSTANCE = Companion.$$INSTANCE;
    public static final String DEFAULT = "legacy";
    public static final String DUMMY = "dummy";
    public static final String DUMMY_WITH_TRACKING = "dummy_with_tracking";
    public static final String EXPERIMENTAL = "experimental";
    public static final String LEGACY = "legacy";
    public static final String LEGACY_DEFAULT_PARAMS = "legacy_default_params";

    /* compiled from: BitmapPoolType.kt */
    @Metadata(d1 = {"\u0000\u0014\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\b\u0003\n\u0002\u0010\u000e\n\u0002\b\u0006\b\u0086\u0003\u0018\u00002\u00020\u0001B\t\b\u0002¢\u0006\u0004\b\u0002\u0010\u0003R\u000e\u0010\u0004\u001a\u00020\u0005X\u0086T¢\u0006\u0002\n\u0000R\u000e\u0010\u0006\u001a\u00020\u0005X\u0086T¢\u0006\u0002\n\u0000R\u000e\u0010\u0007\u001a\u00020\u0005X\u0086T¢\u0006\u0002\n\u0000R\u000e\u0010\b\u001a\u00020\u0005X\u0086T¢\u0006\u0002\n\u0000R\u000e\u0010\t\u001a\u00020\u0005X\u0086T¢\u0006\u0002\n\u0000R\u000e\u0010\n\u001a\u00020\u0005X\u0086T¢\u0006\u0002\n\u0000¨\u0006\u000b"}, d2 = {"Lcom/facebook/imagepipeline/memory/BitmapPoolType$Companion;", "", "<init>", "()V", "LEGACY", "", "LEGACY_DEFAULT_PARAMS", "DUMMY", "DUMMY_WITH_TRACKING", "EXPERIMENTAL", "DEFAULT", "imagepipeline_release"}, k = 1, mv = {2, 0, 0}, xi = 48)
    public static final class Companion {
        static final /* synthetic */ Companion $$INSTANCE = new Companion();
        public static final String DEFAULT = "legacy";
        public static final String DUMMY = "dummy";
        public static final String DUMMY_WITH_TRACKING = "dummy_with_tracking";
        public static final String EXPERIMENTAL = "experimental";
        public static final String LEGACY = "legacy";
        public static final String LEGACY_DEFAULT_PARAMS = "legacy_default_params";

        private Companion() {
        }
    }
}
