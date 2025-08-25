package com.facebook.yoga;

import javax.annotation.Nullable;

/* loaded from: classes.dex */
public abstract class YogaNode implements YogaProps {

    public interface Inputs {
        void freeze(YogaNode yogaNode, @Nullable YogaNode yogaNode2);
    }

    public abstract void addChildAt(YogaNode yogaNode, int i);

    public abstract void calculateLayout(float f, float f2);

    public abstract YogaNode cloneWithChildren();

    public abstract YogaNode cloneWithoutChildren();

    public abstract void copyStyle(YogaNode yogaNode);

    public abstract void dirty();

    @Override // com.facebook.yoga.YogaProps
    public abstract YogaAlign getAlignContent();

    @Override // com.facebook.yoga.YogaProps
    public abstract YogaAlign getAlignItems();

    @Override // com.facebook.yoga.YogaProps
    public abstract YogaAlign getAlignSelf();

    @Override // com.facebook.yoga.YogaProps
    public abstract float getAspectRatio();

    @Override // com.facebook.yoga.YogaProps
    public abstract float getBorder(YogaEdge yogaEdge);

    @Override // com.facebook.yoga.YogaProps
    public abstract YogaBoxSizing getBoxSizing();

    public abstract YogaNode getChildAt(int i);

    public abstract int getChildCount();

    @Nullable
    public abstract Object getData();

    public abstract YogaDisplay getDisplay();

    public abstract float getFlex();

    @Override // com.facebook.yoga.YogaProps
    public abstract YogaValue getFlexBasis();

    @Override // com.facebook.yoga.YogaProps
    public abstract YogaFlexDirection getFlexDirection();

    @Override // com.facebook.yoga.YogaProps
    public abstract float getFlexGrow();

    @Override // com.facebook.yoga.YogaProps
    public abstract float getFlexShrink();

    public abstract YogaValue getGap(YogaGutter yogaGutter);

    @Override // com.facebook.yoga.YogaProps
    public abstract YogaValue getHeight();

    @Override // com.facebook.yoga.YogaProps
    public abstract YogaJustify getJustifyContent();

    public abstract float getLayoutBorder(YogaEdge yogaEdge);

    public abstract YogaDirection getLayoutDirection();

    public abstract float getLayoutHeight();

    public abstract float getLayoutMargin(YogaEdge yogaEdge);

    public abstract float getLayoutPadding(YogaEdge yogaEdge);

    public abstract float getLayoutWidth();

    public abstract float getLayoutX();

    public abstract float getLayoutY();

    @Override // com.facebook.yoga.YogaProps
    public abstract YogaValue getMargin(YogaEdge yogaEdge);

    @Override // com.facebook.yoga.YogaProps
    public abstract YogaValue getMaxHeight();

    @Override // com.facebook.yoga.YogaProps
    public abstract YogaValue getMaxWidth();

    @Override // com.facebook.yoga.YogaProps
    public abstract YogaValue getMinHeight();

    @Override // com.facebook.yoga.YogaProps
    public abstract YogaValue getMinWidth();

    public abstract YogaOverflow getOverflow();

    @Nullable
    public abstract YogaNode getOwner();

    @Override // com.facebook.yoga.YogaProps
    public abstract YogaValue getPadding(YogaEdge yogaEdge);

    @Nullable
    @Deprecated
    public abstract YogaNode getParent();

    @Override // com.facebook.yoga.YogaProps
    public abstract YogaValue getPosition(YogaEdge yogaEdge);

    @Override // com.facebook.yoga.YogaProps
    public abstract YogaPositionType getPositionType();

    @Override // com.facebook.yoga.YogaProps
    public abstract YogaDirection getStyleDirection();

    @Override // com.facebook.yoga.YogaProps
    public abstract YogaValue getWidth();

    public abstract YogaWrap getWrap();

    public abstract boolean hasNewLayout();

    public abstract int indexOf(YogaNode yogaNode);

    public abstract boolean isBaselineDefined();

    public abstract boolean isDirty();

    public abstract boolean isMeasureDefined();

    public abstract boolean isReferenceBaseline();

    public abstract void markLayoutSeen();

    public abstract YogaNode removeChildAt(int i);

    public abstract void reset();

    @Override // com.facebook.yoga.YogaProps
    public abstract void setAlignContent(YogaAlign yogaAlign);

    @Override // com.facebook.yoga.YogaProps
    public abstract void setAlignItems(YogaAlign yogaAlign);

    @Override // com.facebook.yoga.YogaProps
    public abstract void setAlignSelf(YogaAlign yogaAlign);

    public abstract void setAlwaysFormsContainingBlock(boolean z);

    @Override // com.facebook.yoga.YogaProps
    public abstract void setAspectRatio(float f);

    @Override // com.facebook.yoga.YogaProps
    public abstract void setBaselineFunction(YogaBaselineFunction yogaBaselineFunction);

    @Override // com.facebook.yoga.YogaProps
    public abstract void setBorder(YogaEdge yogaEdge, float f);

    @Override // com.facebook.yoga.YogaProps
    public abstract void setBoxSizing(YogaBoxSizing yogaBoxSizing);

    public abstract void setData(Object obj);

    @Override // com.facebook.yoga.YogaProps
    public abstract void setDirection(YogaDirection yogaDirection);

    public abstract void setDisplay(YogaDisplay yogaDisplay);

    @Override // com.facebook.yoga.YogaProps
    public abstract void setFlex(float f);

    @Override // com.facebook.yoga.YogaProps
    public abstract void setFlexBasis(float f);

    @Override // com.facebook.yoga.YogaProps
    public abstract void setFlexBasisAuto();

    @Override // com.facebook.yoga.YogaProps
    public abstract void setFlexBasisFitContent();

    @Override // com.facebook.yoga.YogaProps
    public abstract void setFlexBasisMaxContent();

    @Override // com.facebook.yoga.YogaProps
    public abstract void setFlexBasisPercent(float f);

    @Override // com.facebook.yoga.YogaProps
    public abstract void setFlexBasisStretch();

    @Override // com.facebook.yoga.YogaProps
    public abstract void setFlexDirection(YogaFlexDirection yogaFlexDirection);

    @Override // com.facebook.yoga.YogaProps
    public abstract void setFlexGrow(float f);

    @Override // com.facebook.yoga.YogaProps
    public abstract void setFlexShrink(float f);

    public abstract void setGap(YogaGutter yogaGutter, float f);

    public abstract void setGapPercent(YogaGutter yogaGutter, float f);

    @Override // com.facebook.yoga.YogaProps
    public abstract void setHeight(float f);

    @Override // com.facebook.yoga.YogaProps
    public abstract void setHeightAuto();

    @Override // com.facebook.yoga.YogaProps
    public abstract void setHeightFitContent();

    @Override // com.facebook.yoga.YogaProps
    public abstract void setHeightMaxContent();

    @Override // com.facebook.yoga.YogaProps
    public abstract void setHeightPercent(float f);

    @Override // com.facebook.yoga.YogaProps
    public abstract void setHeightStretch();

    @Override // com.facebook.yoga.YogaProps
    public abstract void setIsReferenceBaseline(boolean z);

    @Override // com.facebook.yoga.YogaProps
    public abstract void setJustifyContent(YogaJustify yogaJustify);

    @Override // com.facebook.yoga.YogaProps
    public abstract void setMargin(YogaEdge yogaEdge, float f);

    @Override // com.facebook.yoga.YogaProps
    public abstract void setMarginAuto(YogaEdge yogaEdge);

    @Override // com.facebook.yoga.YogaProps
    public abstract void setMarginPercent(YogaEdge yogaEdge, float f);

    @Override // com.facebook.yoga.YogaProps
    public abstract void setMaxHeight(float f);

    @Override // com.facebook.yoga.YogaProps
    public abstract void setMaxHeightFitContent();

    @Override // com.facebook.yoga.YogaProps
    public abstract void setMaxHeightMaxContent();

    @Override // com.facebook.yoga.YogaProps
    public abstract void setMaxHeightPercent(float f);

    @Override // com.facebook.yoga.YogaProps
    public abstract void setMaxHeightStretch();

    @Override // com.facebook.yoga.YogaProps
    public abstract void setMaxWidth(float f);

    @Override // com.facebook.yoga.YogaProps
    public abstract void setMaxWidthFitContent();

    @Override // com.facebook.yoga.YogaProps
    public abstract void setMaxWidthMaxContent();

    @Override // com.facebook.yoga.YogaProps
    public abstract void setMaxWidthPercent(float f);

    @Override // com.facebook.yoga.YogaProps
    public abstract void setMaxWidthStretch();

    @Override // com.facebook.yoga.YogaProps
    public abstract void setMeasureFunction(YogaMeasureFunction yogaMeasureFunction);

    @Override // com.facebook.yoga.YogaProps
    public abstract void setMinHeight(float f);

    @Override // com.facebook.yoga.YogaProps
    public abstract void setMinHeightFitContent();

    @Override // com.facebook.yoga.YogaProps
    public abstract void setMinHeightMaxContent();

    @Override // com.facebook.yoga.YogaProps
    public abstract void setMinHeightPercent(float f);

    @Override // com.facebook.yoga.YogaProps
    public abstract void setMinHeightStretch();

    @Override // com.facebook.yoga.YogaProps
    public abstract void setMinWidth(float f);

    @Override // com.facebook.yoga.YogaProps
    public abstract void setMinWidthFitContent();

    @Override // com.facebook.yoga.YogaProps
    public abstract void setMinWidthMaxContent();

    @Override // com.facebook.yoga.YogaProps
    public abstract void setMinWidthPercent(float f);

    @Override // com.facebook.yoga.YogaProps
    public abstract void setMinWidthStretch();

    public abstract void setOverflow(YogaOverflow yogaOverflow);

    @Override // com.facebook.yoga.YogaProps
    public abstract void setPadding(YogaEdge yogaEdge, float f);

    @Override // com.facebook.yoga.YogaProps
    public abstract void setPaddingPercent(YogaEdge yogaEdge, float f);

    @Override // com.facebook.yoga.YogaProps
    public abstract void setPosition(YogaEdge yogaEdge, float f);

    public abstract void setPositionAuto(YogaEdge yogaEdge);

    @Override // com.facebook.yoga.YogaProps
    public abstract void setPositionPercent(YogaEdge yogaEdge, float f);

    @Override // com.facebook.yoga.YogaProps
    public abstract void setPositionType(YogaPositionType yogaPositionType);

    @Override // com.facebook.yoga.YogaProps
    public abstract void setWidth(float f);

    @Override // com.facebook.yoga.YogaProps
    public abstract void setWidthAuto();

    @Override // com.facebook.yoga.YogaProps
    public abstract void setWidthFitContent();

    @Override // com.facebook.yoga.YogaProps
    public abstract void setWidthMaxContent();

    @Override // com.facebook.yoga.YogaProps
    public abstract void setWidthPercent(float f);

    @Override // com.facebook.yoga.YogaProps
    public abstract void setWidthStretch();

    @Override // com.facebook.yoga.YogaProps
    public abstract void setWrap(YogaWrap yogaWrap);
}
