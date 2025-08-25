package com.facebook.hermes.intl;

import android.icu.lang.UCharacter;
import android.icu.util.ULocale;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/* loaded from: classes.dex */
public class Intl {
    private static List<String> canonicalizeLocaleList(List<String> list) throws JSRangeErrorException {
        if (list.size() == 0) {
            return Collections.emptyList();
        }
        ArrayList arrayList = new ArrayList();
        for (String str : list) {
            if (str == null) {
                throw new JSRangeErrorException("Incorrect locale information provided");
            }
            if (str.isEmpty()) {
                throw new JSRangeErrorException("Incorrect locale information provided");
            }
            String strCanonicalizeLocaleId = LocaleIdentifier.canonicalizeLocaleId(str);
            if (!strCanonicalizeLocaleId.isEmpty() && !arrayList.contains(strCanonicalizeLocaleId)) {
                arrayList.add(strCanonicalizeLocaleId);
            }
        }
        return arrayList;
    }

    public static List<String> getCanonicalLocales(List<String> list) throws JSRangeErrorException {
        return canonicalizeLocaleList(list);
    }

    public static String toLocaleLowerCase(List<String> list, String str) throws JSRangeErrorException {
        return UCharacter.toLowerCase((ULocale) LocaleMatcher.bestFitMatch((String[]) list.toArray(new String[list.size()])).matchedLocale.getLocale(), str);
    }

    public static String toLocaleUpperCase(List<String> list, String str) throws JSRangeErrorException {
        return UCharacter.toUpperCase((ULocale) LocaleMatcher.bestFitMatch((String[]) list.toArray(new String[list.size()])).matchedLocale.getLocale(), str);
    }
}
