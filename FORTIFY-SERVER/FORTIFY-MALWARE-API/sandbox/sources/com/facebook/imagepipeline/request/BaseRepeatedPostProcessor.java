package com.facebook.imagepipeline.request;

import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

/* compiled from: BaseRepeatedPostProcessor.kt */
@Metadata(d1 = {"\u0000\u001e\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0002\n\u0002\b\u0003\b&\u0018\u00002\u00020\u00012\u00020\u0002B\u0007¢\u0006\u0004\b\u0003\u0010\u0004J\u0010\u0010\u0007\u001a\u00020\b2\u0006\u0010\t\u001a\u00020\u0006H\u0016J\u0006\u0010\n\u001a\u00020\bR\u0010\u0010\u0005\u001a\u0004\u0018\u00010\u0006X\u0082\u000e¢\u0006\u0002\n\u0000¨\u0006\u000b"}, d2 = {"Lcom/facebook/imagepipeline/request/BaseRepeatedPostProcessor;", "Lcom/facebook/imagepipeline/request/BasePostprocessor;", "Lcom/facebook/imagepipeline/request/RepeatedPostprocessor;", "<init>", "()V", "callback", "Lcom/facebook/imagepipeline/request/RepeatedPostprocessorRunner;", "setCallback", "", "runner", "update", "imagepipeline_release"}, k = 1, mv = {2, 0, 0}, xi = 48)
/* loaded from: classes.dex */
public abstract class BaseRepeatedPostProcessor extends BasePostprocessor implements RepeatedPostprocessor {
    private RepeatedPostprocessorRunner callback;

    @Override // com.facebook.imagepipeline.request.RepeatedPostprocessor
    public synchronized void setCallback(RepeatedPostprocessorRunner runner) {
        Intrinsics.checkNotNullParameter(runner, "runner");
        this.callback = runner;
    }

    public final void update() {
        RepeatedPostprocessorRunner repeatedPostprocessorRunner = this.callback;
        if (repeatedPostprocessorRunner != null) {
            repeatedPostprocessorRunner.update();
        }
    }
}
