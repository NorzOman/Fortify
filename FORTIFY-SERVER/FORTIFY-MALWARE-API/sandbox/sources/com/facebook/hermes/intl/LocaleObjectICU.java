package com.facebook.hermes.intl;

import android.icu.util.ULocale;
import android.text.TextUtils;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;

/* loaded from: classes.dex */
public class LocaleObjectICU implements ILocaleObject<ULocale> {
    static final /* synthetic */ boolean $assertionsDisabled = false;
    private boolean mIsDirty;
    private ULocale m_icuLocale;
    private ULocale.Builder m_icuLocaleBuilder;

    private LocaleObjectICU(ULocale uLocale) {
        this.m_icuLocaleBuilder = null;
        this.mIsDirty = false;
        this.m_icuLocale = uLocale;
    }

    private LocaleObjectICU(String str) throws JSRangeErrorException {
        this.m_icuLocale = null;
        this.m_icuLocaleBuilder = null;
        this.mIsDirty = false;
        ULocale.Builder builder = new ULocale.Builder();
        this.m_icuLocaleBuilder = builder;
        try {
            builder.setLanguageTag(str);
            this.mIsDirty = true;
        } catch (RuntimeException e) {
            throw new JSRangeErrorException(e.getMessage());
        }
    }

    private void ensureNotDirty() throws JSRangeErrorException {
        if (this.mIsDirty) {
            try {
                this.m_icuLocale = this.m_icuLocaleBuilder.build();
                this.mIsDirty = false;
            } catch (RuntimeException e) {
                throw new JSRangeErrorException(e.getMessage());
            }
        }
    }

    @Override // com.facebook.hermes.intl.ILocaleObject
    public ArrayList<String> getUnicodeExtensions(String str) throws JSRangeErrorException {
        ensureNotDirty();
        String strCanonicalKeyToICUKey = UnicodeExtensionKeys.CanonicalKeyToICUKey(str);
        ArrayList<String> arrayList = new ArrayList<>();
        String keywordValue = this.m_icuLocale.getKeywordValue(strCanonicalKeyToICUKey);
        if (keywordValue != null && !keywordValue.isEmpty()) {
            Collections.addAll(arrayList, keywordValue.split("-|_"));
        }
        return arrayList;
    }

    @Override // com.facebook.hermes.intl.ILocaleObject
    public HashMap<String, String> getUnicodeExtensions() throws JSRangeErrorException {
        ensureNotDirty();
        HashMap<String, String> map = new HashMap<>();
        Iterator<String> keywords = this.m_icuLocale.getKeywords();
        if (keywords != null) {
            while (keywords.hasNext()) {
                String next = keywords.next();
                map.put(UnicodeExtensionKeys.ICUKeyToCanonicalKey(next), this.m_icuLocale.getKeywordValue(next));
            }
        }
        return map;
    }

    @Override // com.facebook.hermes.intl.ILocaleObject
    public void setUnicodeExtensions(String str, ArrayList<String> arrayList) throws JSRangeErrorException {
        ensureNotDirty();
        if (this.m_icuLocaleBuilder == null) {
            this.m_icuLocaleBuilder = new ULocale.Builder().setLocale(this.m_icuLocale);
        }
        try {
            this.m_icuLocaleBuilder.setUnicodeLocaleKeyword(str, TextUtils.join("-", arrayList));
            this.mIsDirty = true;
        } catch (RuntimeException e) {
            throw new JSRangeErrorException(e.getMessage());
        }
    }

    /* JADX WARN: Can't rename method to resolve collision */
    @Override // com.facebook.hermes.intl.ILocaleObject
    public ULocale getLocale() throws JSRangeErrorException {
        ensureNotDirty();
        return this.m_icuLocale;
    }

    /* JADX WARN: Can't rename method to resolve collision */
    @Override // com.facebook.hermes.intl.ILocaleObject
    public ULocale getLocaleWithoutExtensions() throws JSRangeErrorException {
        ensureNotDirty();
        ULocale.Builder builder = new ULocale.Builder();
        builder.setLocale(this.m_icuLocale);
        builder.clearExtensions();
        return builder.build();
    }

    @Override // com.facebook.hermes.intl.ILocaleObject
    public String toCanonicalTag() throws JSRangeErrorException {
        return getLocale().toLanguageTag();
    }

    @Override // com.facebook.hermes.intl.ILocaleObject
    public String toCanonicalTagWithoutExtensions() throws JSRangeErrorException {
        return getLocaleWithoutExtensions().toLanguageTag();
    }

    @Override // com.facebook.hermes.intl.ILocaleObject
    public ILocaleObject<ULocale> cloneObject() throws JSRangeErrorException {
        ensureNotDirty();
        return new LocaleObjectICU(this.m_icuLocale);
    }

    public static ILocaleObject<ULocale> createFromLocaleId(String str) throws JSRangeErrorException {
        return new LocaleObjectICU(str);
    }

    public static ILocaleObject<ULocale> createFromULocale(ULocale uLocale) {
        return new LocaleObjectICU(uLocale);
    }

    public static ILocaleObject<ULocale> createDefault() {
        return new LocaleObjectICU(ULocale.getDefault(ULocale.Category.FORMAT));
    }
}
