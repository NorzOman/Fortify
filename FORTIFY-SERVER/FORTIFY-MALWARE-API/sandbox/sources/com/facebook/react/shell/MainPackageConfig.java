package com.facebook.react.shell;

import com.facebook.imagepipeline.core.ImagePipelineConfig;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

/* compiled from: MainPackageConfig.kt */
@Metadata(d1 = {"\u0000\u0012\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0005\u0018\u00002\u00020\u0001B\u000f\u0012\u0006\u0010\u0002\u001a\u00020\u0003¢\u0006\u0004\b\u0004\u0010\u0005R\u0011\u0010\u0002\u001a\u00020\u0003¢\u0006\b\n\u0000\u001a\u0004\b\u0006\u0010\u0007¨\u0006\b"}, d2 = {"Lcom/facebook/react/shell/MainPackageConfig;", "", "frescoConfig", "Lcom/facebook/imagepipeline/core/ImagePipelineConfig;", "<init>", "(Lcom/facebook/imagepipeline/core/ImagePipelineConfig;)V", "getFrescoConfig", "()Lcom/facebook/imagepipeline/core/ImagePipelineConfig;", "ReactAndroid_release"}, k = 1, mv = {2, 0, 0}, xi = 48)
/* loaded from: classes.dex */
public final class MainPackageConfig {
    private final ImagePipelineConfig frescoConfig;

    public MainPackageConfig(ImagePipelineConfig frescoConfig) {
        Intrinsics.checkNotNullParameter(frescoConfig, "frescoConfig");
        this.frescoConfig = frescoConfig;
    }

    public final ImagePipelineConfig getFrescoConfig() {
        return this.frescoConfig;
    }
}
