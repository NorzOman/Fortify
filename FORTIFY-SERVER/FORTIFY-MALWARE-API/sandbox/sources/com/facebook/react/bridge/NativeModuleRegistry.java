package com.facebook.react.bridge;

import com.facebook.infer.annotation.Assertions;
import com.facebook.react.module.annotations.ReactModule;
import com.facebook.react.uimanager.UIManagerModule;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

/* loaded from: classes.dex */
public class NativeModuleRegistry {
    private final String TAG = "NativeModuleRegistry";
    private final Map<String, ModuleHolder> mModules;
    private final ReactApplicationContext mReactApplicationContext;

    public NativeModuleRegistry(ReactApplicationContext reactApplicationContext, Map<String, ModuleHolder> map) {
        this.mReactApplicationContext = reactApplicationContext;
        this.mModules = map;
    }

    private Map<String, ModuleHolder> getModuleMap() {
        return this.mModules;
    }

    private ReactApplicationContext getReactApplicationContext() {
        return this.mReactApplicationContext;
    }

    Collection<JavaModuleWrapper> getJavaModules(JSInstance jSInstance) {
        ArrayList arrayList = new ArrayList();
        for (Map.Entry<String, ModuleHolder> entry : this.mModules.entrySet()) {
            if (!entry.getValue().isCxxModule()) {
                arrayList.add(new JavaModuleWrapper(jSInstance, entry.getValue()));
            }
        }
        return arrayList;
    }

    Collection<ModuleHolder> getCxxModules() {
        ArrayList arrayList = new ArrayList();
        for (Map.Entry<String, ModuleHolder> entry : this.mModules.entrySet()) {
            if (entry.getValue().isCxxModule()) {
                arrayList.add(entry.getValue());
            }
        }
        return arrayList;
    }

    void registerModules(NativeModuleRegistry nativeModuleRegistry) {
        Assertions.assertCondition(this.mReactApplicationContext.equals(nativeModuleRegistry.getReactApplicationContext()), "Extending native modules with non-matching application contexts.");
        for (Map.Entry<String, ModuleHolder> entry : nativeModuleRegistry.getModuleMap().entrySet()) {
            String key = entry.getKey();
            if (!this.mModules.containsKey(key)) {
                this.mModules.put(key, entry.getValue());
            }
        }
    }

    void notifyJSInstanceDestroy() {
        this.mReactApplicationContext.assertOnNativeModulesQueueThread();
        com.facebook.systrace.Systrace.beginSection(0L, "NativeModuleRegistry_notifyJSInstanceDestroy");
        try {
            Iterator<ModuleHolder> it = this.mModules.values().iterator();
            while (it.hasNext()) {
                it.next().destroy();
            }
        } finally {
            com.facebook.systrace.Systrace.endSection(0L);
        }
    }

    void notifyJSInstanceInitialized() {
        this.mReactApplicationContext.assertOnNativeModulesQueueThread("From version React Native v0.44, native modules are explicitly not initialized on the UI thread.");
        ReactMarker.logMarker(ReactMarkerConstants.NATIVE_MODULE_INITIALIZE_START);
        com.facebook.systrace.Systrace.beginSection(0L, "NativeModuleRegistry_notifyJSInstanceInitialized");
        try {
            Iterator<ModuleHolder> it = this.mModules.values().iterator();
            while (it.hasNext()) {
                it.next().markInitializable();
            }
        } finally {
            com.facebook.systrace.Systrace.endSection(0L);
            ReactMarker.logMarker(ReactMarkerConstants.NATIVE_MODULE_INITIALIZE_END);
        }
    }

    public void onBatchComplete() {
        ModuleHolder moduleHolder = this.mModules.get(UIManagerModule.NAME);
        if (moduleHolder == null || !moduleHolder.hasInstance()) {
            return;
        }
        ((OnBatchCompleteListener) moduleHolder.getModule()).onBatchComplete();
    }

    public <T extends NativeModule> boolean hasModule(Class<T> cls) {
        return this.mModules.containsKey(((ReactModule) cls.getAnnotation(ReactModule.class)).name());
    }

    public <T extends NativeModule> T getModule(Class<T> cls) {
        ReactModule reactModule = (ReactModule) cls.getAnnotation(ReactModule.class);
        if (reactModule == null) {
            throw new IllegalArgumentException("Could not find @ReactModule annotation in class " + cls.getName());
        }
        return (T) ((ModuleHolder) Assertions.assertNotNull(this.mModules.get(reactModule.name()), reactModule.name() + " could not be found. Is it defined in " + cls.getName())).getModule();
    }

    public boolean hasModule(String str) {
        return this.mModules.containsKey(str);
    }

    public NativeModule getModule(String str) {
        return ((ModuleHolder) Assertions.assertNotNull(this.mModules.get(str), "Could not find module with name " + str)).getModule();
    }

    public List<NativeModule> getAllModules() {
        ArrayList arrayList = new ArrayList();
        Iterator<ModuleHolder> it = this.mModules.values().iterator();
        while (it.hasNext()) {
            arrayList.add(it.next().getModule());
        }
        return arrayList;
    }
}
