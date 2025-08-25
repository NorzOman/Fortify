package com.facebook.drawee.view;

import android.content.Context;
import android.util.AttributeSet;
import com.facebook.drawee.generic.GenericDraweeHierarchy;
import com.facebook.drawee.generic.GenericDraweeHierarchyBuilder;
import com.facebook.drawee.generic.GenericDraweeHierarchyInflater;
import com.facebook.imagepipeline.systrace.FrescoSystrace;
import javax.annotation.Nullable;

@Deprecated
/* loaded from: classes.dex */
public class GenericDraweeView extends DraweeView<GenericDraweeHierarchy> {
    public GenericDraweeView(Context context, GenericDraweeHierarchy genericDraweeHierarchy) {
        super(context);
        setHierarchy(genericDraweeHierarchy);
    }

    public GenericDraweeView(Context context) throws Throwable {
        super(context);
        inflateHierarchy(context, null);
    }

    public GenericDraweeView(Context context, @Nullable AttributeSet attributeSet) throws Throwable {
        super(context, attributeSet);
        inflateHierarchy(context, attributeSet);
    }

    public GenericDraweeView(Context context, @Nullable AttributeSet attributeSet, int i) throws Throwable {
        super(context, attributeSet, i);
        inflateHierarchy(context, attributeSet);
    }

    public GenericDraweeView(Context context, AttributeSet attributeSet, int i, int i2) throws Throwable {
        super(context, attributeSet, i, i2);
        inflateHierarchy(context, attributeSet);
    }

    protected void inflateHierarchy(Context context, @Nullable AttributeSet attributeSet) throws Throwable {
        if (FrescoSystrace.isTracing()) {
            FrescoSystrace.beginSection("GenericDraweeView#inflateHierarchy");
        }
        GenericDraweeHierarchyBuilder genericDraweeHierarchyBuilderInflateBuilder = GenericDraweeHierarchyInflater.inflateBuilder(context, attributeSet);
        setAspectRatio(genericDraweeHierarchyBuilderInflateBuilder.getDesiredAspectRatio());
        setHierarchy(genericDraweeHierarchyBuilderInflateBuilder.build());
        if (FrescoSystrace.isTracing()) {
            FrescoSystrace.endSection();
        }
    }
}
