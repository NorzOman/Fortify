package com.facebook.hermes.intl;

import com.facebook.hermes.intl.LocaleMatcher;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;

/* loaded from: classes.dex */
public class LocaleResolver {
    public static HashMap<String, Object> resolveLocale(List<String> list, Object obj, List<String> list2) throws JSRangeErrorException {
        LocaleMatcher.LocaleMatchResult localeMatchResultBestFitMatch;
        HashMap<String, Object> map = new HashMap<>();
        if (JSObjects.getJavaString(JSObjects.Get(obj, Constants.LOCALEMATCHER)).equals(Constants.LOCALEMATCHER_LOOKUP)) {
            localeMatchResultBestFitMatch = LocaleMatcher.lookupMatch((String[]) list.toArray(new String[list.size()]));
        } else {
            localeMatchResultBestFitMatch = LocaleMatcher.bestFitMatch((String[]) list.toArray(new String[list.size()]));
        }
        HashSet<String> hashSet = new HashSet();
        for (String str : list2) {
            Object objNull = JSObjects.Null();
            Object obj2 = objNull;
            if (!localeMatchResultBestFitMatch.extensions.isEmpty()) {
                obj2 = objNull;
                if (localeMatchResultBestFitMatch.extensions.containsKey(str)) {
                    String str2 = localeMatchResultBestFitMatch.extensions.get(str);
                    boolean zIsEmpty = str2.isEmpty();
                    Object objNewString = str2;
                    if (zIsEmpty) {
                        objNewString = JSObjects.newString("true");
                    }
                    hashSet.add(str);
                    obj2 = objNewString;
                }
            }
            Object obj3 = obj2;
            if (JSObjects.getJavaMap(obj).containsKey(str)) {
                Object objGet = JSObjects.Get(obj, str);
                boolean zIsString = JSObjects.isString(objGet);
                Object objNewBoolean = objGet;
                if (zIsString) {
                    boolean zIsEmpty2 = JSObjects.getJavaString(objGet).isEmpty();
                    objNewBoolean = objGet;
                    if (zIsEmpty2) {
                        objNewBoolean = JSObjects.newBoolean(true);
                    }
                }
                obj3 = obj2;
                if (!JSObjects.isUndefined(objNewBoolean)) {
                    boolean zEquals = objNewBoolean.equals(obj2);
                    obj3 = obj2;
                    if (!zEquals) {
                        hashSet.remove(str);
                        obj3 = objNewBoolean;
                    }
                }
            }
            boolean zIsNull = JSObjects.isNull(obj3);
            Object objResolveKnownAliases = obj3;
            if (!zIsNull) {
                objResolveKnownAliases = UnicodeExtensionKeys.resolveKnownAliases(str, obj3);
            }
            if (JSObjects.isString(objResolveKnownAliases) && !UnicodeExtensionKeys.isValidKeyword(str, JSObjects.getJavaString(objResolveKnownAliases), localeMatchResultBestFitMatch.matchedLocale)) {
                map.put(str, JSObjects.Null());
            } else {
                map.put(str, objResolveKnownAliases);
            }
        }
        for (String str3 : hashSet) {
            ArrayList<String> arrayList = new ArrayList<>();
            String javaString = JSObjects.getJavaString(UnicodeExtensionKeys.resolveKnownAliases(str3, JSObjects.newString(localeMatchResultBestFitMatch.extensions.get(str3))));
            if (!JSObjects.isString(javaString) || UnicodeExtensionKeys.isValidKeyword(str3, JSObjects.getJavaString(javaString), localeMatchResultBestFitMatch.matchedLocale)) {
                arrayList.add(javaString);
                localeMatchResultBestFitMatch.matchedLocale.setUnicodeExtensions(str3, arrayList);
            }
        }
        map.put(Constants.LOCALE, localeMatchResultBestFitMatch.matchedLocale);
        return map;
    }
}
