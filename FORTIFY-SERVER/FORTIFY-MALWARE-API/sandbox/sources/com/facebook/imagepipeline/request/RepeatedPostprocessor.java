package com.facebook.imagepipeline.request;

import kotlin.Metadata;

/* compiled from: RepeatedPostprocessor.kt */
@Metadata(d1 = {"\u0000\u0016\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\bf\u0018\u00002\u00020\u0001J\u0010\u0010\u0002\u001a\u00020\u00032\u0006\u0010\u0004\u001a\u00020\u0005H&¨\u0006\u0006"}, d2 = {"Lcom/facebook/imagepipeline/request/RepeatedPostprocessor;", "Lcom/facebook/imagepipeline/request/Postprocessor;", "setCallback", "", "runner", "Lcom/facebook/imagepipeline/request/RepeatedPostprocessorRunner;", "imagepipeline_release"}, k = 1, mv = {2, 0, 0}, xi = 48)
/* loaded from: classes.dex */
public interface RepeatedPostprocessor extends Postprocessor {
    void setCallback(RepeatedPostprocessorRunner runner);
}
