package com.facebook.imagepipeline.producers;

import kotlin.Metadata;

/* compiled from: ProducerContextCallbacks.kt */
@Metadata(d1 = {"\u0000\u0012\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0000\n\u0002\u0010\u0002\n\u0002\b\u0004\bf\u0018\u00002\u00020\u0001J\b\u0010\u0002\u001a\u00020\u0003H&J\b\u0010\u0004\u001a\u00020\u0003H&J\b\u0010\u0005\u001a\u00020\u0003H&J\b\u0010\u0006\u001a\u00020\u0003H&¨\u0006\u0007"}, d2 = {"Lcom/facebook/imagepipeline/producers/ProducerContextCallbacks;", "", "onCancellationRequested", "", "onIsPrefetchChanged", "onIsIntermediateResultExpectedChanged", "onPriorityChanged", "imagepipeline_release"}, k = 1, mv = {2, 0, 0}, xi = 48)
/* loaded from: classes.dex */
public interface ProducerContextCallbacks {
    void onCancellationRequested();

    void onIsIntermediateResultExpectedChanged();

    void onIsPrefetchChanged();

    void onPriorityChanged();
}
