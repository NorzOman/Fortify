package com.facebook.imagepipeline.producers;

import com.facebook.imagepipeline.common.Priority;
import com.facebook.imagepipeline.core.ImagePipelineConfigInterface;
import com.facebook.imagepipeline.request.ImageRequest;
import javax.annotation.Nullable;

/* loaded from: classes.dex */
public class SettableProducerContext extends BaseProducerContext {
    public SettableProducerContext(ProducerContext producerContext) {
        this(producerContext.getImageRequest(), producerContext.getId(), producerContext.getUiComponentId(), producerContext.getProducerListener(), producerContext.getCallerContext(), producerContext.getLowestPermittedRequestLevel(), producerContext.isPrefetch(), producerContext.isIntermediateResultExpected(), producerContext.getPriority(), producerContext.getImagePipelineConfig());
    }

    public SettableProducerContext(ImageRequest imageRequest, ProducerContext producerContext) {
        this(imageRequest, producerContext.getId(), producerContext.getUiComponentId(), producerContext.getProducerListener(), producerContext.getCallerContext(), producerContext.getLowestPermittedRequestLevel(), producerContext.isPrefetch(), producerContext.isIntermediateResultExpected(), producerContext.getPriority(), producerContext.getImagePipelineConfig());
    }

    public SettableProducerContext(ImageRequest imageRequest, String str, ProducerListener2 producerListener2, @Nullable Object obj, ImageRequest.RequestLevel requestLevel, boolean z, boolean z2, Priority priority, ImagePipelineConfigInterface imagePipelineConfigInterface) {
        super(imageRequest, str, producerListener2, obj, requestLevel, z, z2, priority, imagePipelineConfigInterface);
    }

    public SettableProducerContext(ImageRequest imageRequest, String str, @Nullable String str2, ProducerListener2 producerListener2, @Nullable Object obj, ImageRequest.RequestLevel requestLevel, boolean z, boolean z2, Priority priority, ImagePipelineConfigInterface imagePipelineConfigInterface) {
        super(imageRequest, str, str2, null, producerListener2, obj, requestLevel, z, z2, priority, imagePipelineConfigInterface);
    }

    public void setIsPrefetch(boolean z) {
        BaseProducerContext.callOnIsPrefetchChanged(setIsPrefetchNoCallbacks(z));
    }

    public void setIsIntermediateResultExpected(boolean z) {
        BaseProducerContext.callOnIsIntermediateResultExpectedChanged(setIsIntermediateResultExpectedNoCallbacks(z));
    }

    public void setPriority(Priority priority) {
        BaseProducerContext.callOnPriorityChanged(setPriorityNoCallbacks(priority));
    }
}
