package com.facebook.yoga;

/* loaded from: classes.dex */
public interface YogaProps {
    YogaAlign getAlignContent();

    YogaAlign getAlignItems();

    YogaAlign getAlignSelf();

    float getAspectRatio();

    float getBorder(YogaEdge yogaEdge);

    YogaBoxSizing getBoxSizing();

    YogaValue getFlexBasis();

    YogaFlexDirection getFlexDirection();

    float getFlexGrow();

    float getFlexShrink();

    YogaValue getHeight();

    YogaJustify getJustifyContent();

    YogaValue getMargin(YogaEdge yogaEdge);

    YogaValue getMaxHeight();

    YogaValue getMaxWidth();

    YogaValue getMinHeight();

    YogaValue getMinWidth();

    YogaValue getPadding(YogaEdge yogaEdge);

    YogaValue getPosition(YogaEdge yogaEdge);

    YogaPositionType getPositionType();

    YogaDirection getStyleDirection();

    YogaValue getWidth();

    void setAlignContent(YogaAlign yogaAlign);

    void setAlignItems(YogaAlign yogaAlign);

    void setAlignSelf(YogaAlign yogaAlign);

    void setAspectRatio(float f);

    void setBaselineFunction(YogaBaselineFunction yogaBaselineFunction);

    void setBorder(YogaEdge yogaEdge, float f);

    void setBoxSizing(YogaBoxSizing yogaBoxSizing);

    void setDirection(YogaDirection yogaDirection);

    void setFlex(float f);

    void setFlexBasis(float f);

    void setFlexBasisAuto();

    void setFlexBasisFitContent();

    void setFlexBasisMaxContent();

    void setFlexBasisPercent(float f);

    void setFlexBasisStretch();

    void setFlexDirection(YogaFlexDirection yogaFlexDirection);

    void setFlexGrow(float f);

    void setFlexShrink(float f);

    void setHeight(float f);

    void setHeightAuto();

    void setHeightFitContent();

    void setHeightMaxContent();

    void setHeightPercent(float f);

    void setHeightStretch();

    void setIsReferenceBaseline(boolean z);

    void setJustifyContent(YogaJustify yogaJustify);

    void setMargin(YogaEdge yogaEdge, float f);

    void setMarginAuto(YogaEdge yogaEdge);

    void setMarginPercent(YogaEdge yogaEdge, float f);

    void setMaxHeight(float f);

    void setMaxHeightFitContent();

    void setMaxHeightMaxContent();

    void setMaxHeightPercent(float f);

    void setMaxHeightStretch();

    void setMaxWidth(float f);

    void setMaxWidthFitContent();

    void setMaxWidthMaxContent();

    void setMaxWidthPercent(float f);

    void setMaxWidthStretch();

    void setMeasureFunction(YogaMeasureFunction yogaMeasureFunction);

    void setMinHeight(float f);

    void setMinHeightFitContent();

    void setMinHeightMaxContent();

    void setMinHeightPercent(float f);

    void setMinHeightStretch();

    void setMinWidth(float f);

    void setMinWidthFitContent();

    void setMinWidthMaxContent();

    void setMinWidthPercent(float f);

    void setMinWidthStretch();

    void setPadding(YogaEdge yogaEdge, float f);

    void setPaddingPercent(YogaEdge yogaEdge, float f);

    void setPosition(YogaEdge yogaEdge, float f);

    void setPositionPercent(YogaEdge yogaEdge, float f);

    void setPositionType(YogaPositionType yogaPositionType);

    void setWidth(float f);

    void setWidthAuto();

    void setWidthFitContent();

    void setWidthMaxContent();

    void setWidthPercent(float f);

    void setWidthStretch();

    void setWrap(YogaWrap yogaWrap);
}
