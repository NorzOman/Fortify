package com.facebook.imagepipeline.common;

import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import kotlin.Metadata;
import kotlin.annotation.AnnotationRetention;

/* compiled from: SourceUriType.kt */
@Retention(RetentionPolicy.SOURCE)
@Metadata(d1 = {"\u0000\f\n\u0002\u0018\u0002\n\u0002\u0010\u001b\n\u0002\b\u0002\b\u0087\u0002\u0018\u0000 \u00022\u00020\u0001:\u0001\u0002B\u0000¨\u0006\u0003"}, d2 = {"Lcom/facebook/imagepipeline/common/SourceUriType;", "", "Companion", "imagepipeline-base_release"}, k = 1, mv = {2, 0, 0}, xi = 48)
@kotlin.annotation.Retention(AnnotationRetention.SOURCE)
/* loaded from: classes.dex */
public @interface SourceUriType {

    /* renamed from: Companion, reason: from kotlin metadata */
    public static final Companion INSTANCE = Companion.$$INSTANCE;
    public static final int SOURCE_TYPE_DATA = 7;
    public static final int SOURCE_TYPE_LOCAL_ASSET = 5;
    public static final int SOURCE_TYPE_LOCAL_CONTENT = 4;
    public static final int SOURCE_TYPE_LOCAL_FILE = 1;
    public static final int SOURCE_TYPE_LOCAL_IMAGE_FILE = 3;
    public static final int SOURCE_TYPE_LOCAL_RESOURCE = 6;
    public static final int SOURCE_TYPE_LOCAL_VIDEO_FILE = 2;
    public static final int SOURCE_TYPE_NETWORK = 0;
    public static final int SOURCE_TYPE_QUALIFIED_RESOURCE = 8;
    public static final int SOURCE_TYPE_UNKNOWN = -1;

    /* compiled from: SourceUriType.kt */
    @Metadata(d1 = {"\u0000\u0014\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\b\u0003\n\u0002\u0010\b\n\u0002\b\n\b\u0086\u0003\u0018\u00002\u00020\u0001B\t\b\u0002¢\u0006\u0004\b\u0002\u0010\u0003R\u000e\u0010\u0004\u001a\u00020\u0005X\u0086T¢\u0006\u0002\n\u0000R\u000e\u0010\u0006\u001a\u00020\u0005X\u0086T¢\u0006\u0002\n\u0000R\u000e\u0010\u0007\u001a\u00020\u0005X\u0086T¢\u0006\u0002\n\u0000R\u000e\u0010\b\u001a\u00020\u0005X\u0086T¢\u0006\u0002\n\u0000R\u000e\u0010\t\u001a\u00020\u0005X\u0086T¢\u0006\u0002\n\u0000R\u000e\u0010\n\u001a\u00020\u0005X\u0086T¢\u0006\u0002\n\u0000R\u000e\u0010\u000b\u001a\u00020\u0005X\u0086T¢\u0006\u0002\n\u0000R\u000e\u0010\f\u001a\u00020\u0005X\u0086T¢\u0006\u0002\n\u0000R\u000e\u0010\r\u001a\u00020\u0005X\u0086T¢\u0006\u0002\n\u0000R\u000e\u0010\u000e\u001a\u00020\u0005X\u0086T¢\u0006\u0002\n\u0000¨\u0006\u000f"}, d2 = {"Lcom/facebook/imagepipeline/common/SourceUriType$Companion;", "", "<init>", "()V", "SOURCE_TYPE_UNKNOWN", "", "SOURCE_TYPE_NETWORK", "SOURCE_TYPE_LOCAL_FILE", "SOURCE_TYPE_LOCAL_VIDEO_FILE", "SOURCE_TYPE_LOCAL_IMAGE_FILE", "SOURCE_TYPE_LOCAL_CONTENT", "SOURCE_TYPE_LOCAL_ASSET", "SOURCE_TYPE_LOCAL_RESOURCE", "SOURCE_TYPE_DATA", "SOURCE_TYPE_QUALIFIED_RESOURCE", "imagepipeline-base_release"}, k = 1, mv = {2, 0, 0}, xi = 48)
    public static final class Companion {
        static final /* synthetic */ Companion $$INSTANCE = new Companion();
        public static final int SOURCE_TYPE_DATA = 7;
        public static final int SOURCE_TYPE_LOCAL_ASSET = 5;
        public static final int SOURCE_TYPE_LOCAL_CONTENT = 4;
        public static final int SOURCE_TYPE_LOCAL_FILE = 1;
        public static final int SOURCE_TYPE_LOCAL_IMAGE_FILE = 3;
        public static final int SOURCE_TYPE_LOCAL_RESOURCE = 6;
        public static final int SOURCE_TYPE_LOCAL_VIDEO_FILE = 2;
        public static final int SOURCE_TYPE_NETWORK = 0;
        public static final int SOURCE_TYPE_QUALIFIED_RESOURCE = 8;
        public static final int SOURCE_TYPE_UNKNOWN = -1;

        private Companion() {
        }
    }
}
