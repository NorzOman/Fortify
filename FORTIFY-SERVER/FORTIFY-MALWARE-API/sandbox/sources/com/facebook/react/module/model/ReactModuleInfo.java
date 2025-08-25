package com.facebook.react.module.model;

import com.facebook.react.turbomodule.core.interfaces.TurboModule;
import kotlin.Deprecated;
import kotlin.DeprecationLevel;
import kotlin.Metadata;
import kotlin.ReplaceWith;
import kotlin.jvm.JvmStatic;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;

/* compiled from: ReactModuleInfo.kt */
@Metadata(d1 = {"\u0000\u001a\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0000\n\u0002\u0010\u000e\n\u0002\b\u0002\n\u0002\u0010\u000b\n\u0002\b\u000b\u0018\u0000 \u00102\u00020\u0001:\u0001\u0010B7\u0012\u0006\u0010\u0002\u001a\u00020\u0003\u0012\u0006\u0010\u0004\u001a\u00020\u0003\u0012\u0006\u0010\u0005\u001a\u00020\u0006\u0012\u0006\u0010\u0007\u001a\u00020\u0006\u0012\u0006\u0010\b\u001a\u00020\u0006\u0012\u0006\u0010\t\u001a\u00020\u0006¢\u0006\u0004\b\n\u0010\u000bBA\b\u0017\u0012\u0006\u0010\u0002\u001a\u00020\u0003\u0012\u0006\u0010\u0004\u001a\u00020\u0003\u0012\u0006\u0010\u0005\u001a\u00020\u0006\u0012\u0006\u0010\u0007\u001a\u00020\u0006\u0012\u0006\u0010\f\u001a\u00020\u0006\u0012\u0006\u0010\b\u001a\u00020\u0006\u0012\u0006\u0010\t\u001a\u00020\u0006¢\u0006\u0004\b\n\u0010\rR\u0013\u0010\u0002\u001a\u00020\u00038G¢\u0006\b\n\u0000\u001a\u0004\b\u0002\u0010\u000eR\u0013\u0010\u0004\u001a\u00020\u00038G¢\u0006\b\n\u0000\u001a\u0004\b\u0004\u0010\u000eR\u0013\u0010\u0005\u001a\u00020\u00068G¢\u0006\b\n\u0000\u001a\u0004\b\u0005\u0010\u000fR\u0013\u0010\u0007\u001a\u00020\u00068G¢\u0006\b\n\u0000\u001a\u0004\b\u0007\u0010\u000fR\u0011\u0010\b\u001a\u00020\u0006¢\u0006\b\n\u0000\u001a\u0004\b\b\u0010\u000fR\u0011\u0010\t\u001a\u00020\u0006¢\u0006\b\n\u0000\u001a\u0004\b\t\u0010\u000f¨\u0006\u0011"}, d2 = {"Lcom/facebook/react/module/model/ReactModuleInfo;", "", "name", "", "className", "canOverrideExistingModule", "", "needsEagerInit", "isCxxModule", "isTurboModule", "<init>", "(Ljava/lang/String;Ljava/lang/String;ZZZZ)V", "hasConstants", "(Ljava/lang/String;Ljava/lang/String;ZZZZZ)V", "()Ljava/lang/String;", "()Z", "Companion", "ReactAndroid_release"}, k = 1, mv = {2, 0, 0}, xi = 48)
/* loaded from: classes.dex */
public final class ReactModuleInfo {

    /* renamed from: Companion, reason: from kotlin metadata */
    public static final Companion INSTANCE = new Companion(null);
    private final boolean canOverrideExistingModule;
    private final String className;
    private final boolean isCxxModule;
    private final boolean isTurboModule;
    private final String name;
    private final boolean needsEagerInit;

    @JvmStatic
    public static final boolean classIsTurboModule(Class<?> cls) {
        return INSTANCE.classIsTurboModule(cls);
    }

    public ReactModuleInfo(String name, String className, boolean z, boolean z2, boolean z3, boolean z4) {
        Intrinsics.checkNotNullParameter(name, "name");
        Intrinsics.checkNotNullParameter(className, "className");
        this.name = name;
        this.className = className;
        this.canOverrideExistingModule = z;
        this.needsEagerInit = z2;
        this.isCxxModule = z3;
        this.isTurboModule = z4;
    }

    /* renamed from: name, reason: from getter */
    public final String getName() {
        return this.name;
    }

    /* renamed from: className, reason: from getter */
    public final String getClassName() {
        return this.className;
    }

    /* renamed from: canOverrideExistingModule, reason: from getter */
    public final boolean getCanOverrideExistingModule() {
        return this.canOverrideExistingModule;
    }

    /* renamed from: needsEagerInit, reason: from getter */
    public final boolean getNeedsEagerInit() {
        return this.needsEagerInit;
    }

    /* renamed from: isCxxModule, reason: from getter */
    public final boolean getIsCxxModule() {
        return this.isCxxModule;
    }

    /* renamed from: isTurboModule, reason: from getter */
    public final boolean getIsTurboModule() {
        return this.isTurboModule;
    }

    /* JADX WARN: 'this' call moved to the top of the method (can break code semantics) */
    @Deprecated(level = DeprecationLevel.WARNING, message = "This constructor is deprecated and will be removed in the future. Use ReactModuleInfo(String, String, boolean, boolean, boolean, boolean)]", replaceWith = @ReplaceWith(expression = "ReactModuleInfo(name, className, canOverrideExistingModule, needsEagerInit, isCxxModule, isTurboModule)", imports = {}))
    public ReactModuleInfo(String name, String className, boolean z, boolean z2, boolean z3, boolean z4, boolean z5) {
        this(name, className, z, z2, z4, z5);
        Intrinsics.checkNotNullParameter(name, "name");
        Intrinsics.checkNotNullParameter(className, "className");
    }

    /* compiled from: ReactModuleInfo.kt */
    @Metadata(d1 = {"\u0000\u0018\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\b\u0003\n\u0002\u0010\u000b\n\u0000\n\u0002\u0018\u0002\n\u0000\b\u0086\u0003\u0018\u00002\u00020\u0001B\t\b\u0002¢\u0006\u0004\b\u0002\u0010\u0003J\u0014\u0010\u0004\u001a\u00020\u00052\n\u0010\u0006\u001a\u0006\u0012\u0002\b\u00030\u0007H\u0007¨\u0006\b"}, d2 = {"Lcom/facebook/react/module/model/ReactModuleInfo$Companion;", "", "<init>", "()V", "classIsTurboModule", "", "clazz", "Ljava/lang/Class;", "ReactAndroid_release"}, k = 1, mv = {2, 0, 0}, xi = 48)
    public static final class Companion {
        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        private Companion() {
        }

        @JvmStatic
        public final boolean classIsTurboModule(Class<?> clazz) {
            Intrinsics.checkNotNullParameter(clazz, "clazz");
            return TurboModule.class.isAssignableFrom(clazz);
        }
    }
}
