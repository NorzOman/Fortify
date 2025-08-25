package com.facebook.imagepipeline.producers;

import com.facebook.fresco.middleware.HasExtraData;
import com.facebook.imagepipeline.common.Priority;
import com.facebook.imagepipeline.core.ImagePipelineConfigInterface;
import com.facebook.imagepipeline.request.ImageRequest;
import kotlin.Metadata;

/* compiled from: ProducerContext.kt */
@Metadata(d1 = {"\u0000V\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0010\u000e\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0010\u0000\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0010\u000b\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0010\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0006\bf\u0018\u00002\u00020\u0001J\u0010\u0010 \u001a\u00020!2\u0006\u0010\"\u001a\u00020#H&J\u001c\u0010(\u001a\u00020!2\b\u0010)\u001a\u0004\u0018\u00010\u00072\b\u0010*\u001a\u0004\u0018\u00010\u0007H&J\u0012\u0010(\u001a\u00020!2\b\u0010)\u001a\u0004\u0018\u00010\u0007H&R\u0012\u0010\u0002\u001a\u00020\u0003X¦\u0004¢\u0006\u0006\u001a\u0004\b\u0004\u0010\u0005R\u0012\u0010\u0006\u001a\u00020\u0007X¦\u0004¢\u0006\u0006\u001a\u0004\b\b\u0010\tR\u0014\u0010\n\u001a\u0004\u0018\u00010\u0007X¦\u0004¢\u0006\u0006\u001a\u0004\b\u000b\u0010\tR\u0012\u0010\f\u001a\u00020\rX¦\u0004¢\u0006\u0006\u001a\u0004\b\u000e\u0010\u000fR\u0012\u0010\u0010\u001a\u00020\u0011X¦\u0004¢\u0006\u0006\u001a\u0004\b\u0012\u0010\u0013R\u0012\u0010\u0014\u001a\u00020\u0015X¦\u0004¢\u0006\u0006\u001a\u0004\b\u0016\u0010\u0017R\u0012\u0010\u0018\u001a\u00020\u0019X¦\u0004¢\u0006\u0006\u001a\u0004\b\u0018\u0010\u001aR\u0012\u0010\u001b\u001a\u00020\u001cX¦\u0004¢\u0006\u0006\u001a\u0004\b\u001d\u0010\u001eR\u0012\u0010\u001f\u001a\u00020\u0019X¦\u0004¢\u0006\u0006\u001a\u0004\b\u001f\u0010\u001aR\u0012\u0010$\u001a\u00020%X¦\u0004¢\u0006\u0006\u001a\u0004\b&\u0010'¨\u0006+"}, d2 = {"Lcom/facebook/imagepipeline/producers/ProducerContext;", "Lcom/facebook/fresco/middleware/HasExtraData;", "imageRequest", "Lcom/facebook/imagepipeline/request/ImageRequest;", "getImageRequest", "()Lcom/facebook/imagepipeline/request/ImageRequest;", "id", "", "getId", "()Ljava/lang/String;", "uiComponentId", "getUiComponentId", "producerListener", "Lcom/facebook/imagepipeline/producers/ProducerListener2;", "getProducerListener", "()Lcom/facebook/imagepipeline/producers/ProducerListener2;", "callerContext", "", "getCallerContext", "()Ljava/lang/Object;", "lowestPermittedRequestLevel", "Lcom/facebook/imagepipeline/request/ImageRequest$RequestLevel;", "getLowestPermittedRequestLevel", "()Lcom/facebook/imagepipeline/request/ImageRequest$RequestLevel;", "isPrefetch", "", "()Z", "priority", "Lcom/facebook/imagepipeline/common/Priority;", "getPriority", "()Lcom/facebook/imagepipeline/common/Priority;", "isIntermediateResultExpected", "addCallbacks", "", "callbacks", "Lcom/facebook/imagepipeline/producers/ProducerContextCallbacks;", "imagePipelineConfig", "Lcom/facebook/imagepipeline/core/ImagePipelineConfigInterface;", "getImagePipelineConfig", "()Lcom/facebook/imagepipeline/core/ImagePipelineConfigInterface;", "putOriginExtra", "origin", "subcategory", "imagepipeline_release"}, k = 1, mv = {2, 0, 0}, xi = 48)
/* loaded from: classes.dex */
public interface ProducerContext extends HasExtraData {
    void addCallbacks(ProducerContextCallbacks callbacks);

    Object getCallerContext();

    String getId();

    ImagePipelineConfigInterface getImagePipelineConfig();

    ImageRequest getImageRequest();

    ImageRequest.RequestLevel getLowestPermittedRequestLevel();

    Priority getPriority();

    ProducerListener2 getProducerListener();

    String getUiComponentId();

    boolean isIntermediateResultExpected();

    boolean isPrefetch();

    void putOriginExtra(String origin);

    void putOriginExtra(String origin, String subcategory);
}
