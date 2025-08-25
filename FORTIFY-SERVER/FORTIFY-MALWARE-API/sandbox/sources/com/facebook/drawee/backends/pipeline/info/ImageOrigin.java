package com.facebook.drawee.backends.pipeline.info;

import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import kotlin.Metadata;
import kotlin.annotation.AnnotationRetention;

/* compiled from: ImageOrigin.kt */
@Retention(RetentionPolicy.SOURCE)
@Metadata(d1 = {"\u0000\f\n\u0002\u0018\u0002\n\u0002\u0010\u001b\n\u0002\b\u0002\b\u0087\u0002\u0018\u0000 \u00022\u00020\u0001:\u0001\u0002B\u0000¨\u0006\u0003"}, d2 = {"Lcom/facebook/drawee/backends/pipeline/info/ImageOrigin;", "", "Companion", "drawee-pipeline_release"}, k = 1, mv = {2, 0, 0}, xi = 48)
@kotlin.annotation.Retention(AnnotationRetention.SOURCE)
/* loaded from: classes.dex */
public @interface ImageOrigin {

    /* renamed from: Companion, reason: from kotlin metadata */
    public static final Companion INSTANCE = Companion.$$INSTANCE;
    public static final int DISK = 3;
    public static final int LOCAL = 7;
    public static final int MEMORY_BITMAP = 5;
    public static final int MEMORY_BITMAP_SHORTCUT = 6;
    public static final int MEMORY_ENCODED = 4;
    public static final int NETWORK = 2;
    public static final int UNKNOWN = 1;

    /* compiled from: ImageOrigin.kt */
    @Metadata(d1 = {"\u0000\u0014\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\b\u0003\n\u0002\u0010\b\n\u0002\b\u0007\b\u0086\u0003\u0018\u00002\u00020\u0001B\t\b\u0002¢\u0006\u0004\b\u0002\u0010\u0003R\u000e\u0010\u0004\u001a\u00020\u0005X\u0086T¢\u0006\u0002\n\u0000R\u000e\u0010\u0006\u001a\u00020\u0005X\u0086T¢\u0006\u0002\n\u0000R\u000e\u0010\u0007\u001a\u00020\u0005X\u0086T¢\u0006\u0002\n\u0000R\u000e\u0010\b\u001a\u00020\u0005X\u0086T¢\u0006\u0002\n\u0000R\u000e\u0010\t\u001a\u00020\u0005X\u0086T¢\u0006\u0002\n\u0000R\u000e\u0010\n\u001a\u00020\u0005X\u0086T¢\u0006\u0002\n\u0000R\u000e\u0010\u000b\u001a\u00020\u0005X\u0086T¢\u0006\u0002\n\u0000¨\u0006\f"}, d2 = {"Lcom/facebook/drawee/backends/pipeline/info/ImageOrigin$Companion;", "", "<init>", "()V", "UNKNOWN", "", "NETWORK", "DISK", "MEMORY_ENCODED", "MEMORY_BITMAP", "MEMORY_BITMAP_SHORTCUT", "LOCAL", "drawee-pipeline_release"}, k = 1, mv = {2, 0, 0}, xi = 48)
    public static final class Companion {
        static final /* synthetic */ Companion $$INSTANCE = new Companion();
        public static final int DISK = 3;
        public static final int LOCAL = 7;
        public static final int MEMORY_BITMAP = 5;
        public static final int MEMORY_BITMAP_SHORTCUT = 6;
        public static final int MEMORY_ENCODED = 4;
        public static final int NETWORK = 2;
        public static final int UNKNOWN = 1;

        private Companion() {
        }
    }
}
