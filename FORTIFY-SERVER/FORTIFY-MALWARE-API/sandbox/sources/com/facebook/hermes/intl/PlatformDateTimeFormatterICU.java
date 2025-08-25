package com.facebook.hermes.intl;

import android.icu.text.DateFormat;
import android.icu.text.NumberingSystem;
import android.icu.text.SimpleDateFormat;
import android.icu.util.Calendar;
import android.icu.util.TimeZone;
import android.icu.util.ULocale;
import androidx.core.text.util.LocalePreferences;
import com.facebook.hermes.intl.IPlatformDateTimeFormatter;
import java.text.AttributedCharacterIterator;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;

/* loaded from: classes.dex */
public class PlatformDateTimeFormatterICU implements IPlatformDateTimeFormatter {
    private DateFormat mDateFormat = null;

    @Override // com.facebook.hermes.intl.IPlatformDateTimeFormatter
    public String format(double d) {
        return this.mDateFormat.format(new Date((long) d));
    }

    @Override // com.facebook.hermes.intl.IPlatformDateTimeFormatter
    public String fieldToString(AttributedCharacterIterator.Attribute attribute, String str) throws NumberFormatException {
        if (attribute == DateFormat.Field.DAY_OF_WEEK) {
            return "weekday";
        }
        if (attribute == DateFormat.Field.ERA) {
            return "era";
        }
        if (attribute == DateFormat.Field.YEAR) {
            try {
                Double.parseDouble(str);
                return "year";
            } catch (NumberFormatException unused) {
                return "yearName";
            }
        }
        if (attribute == DateFormat.Field.MONTH) {
            return "month";
        }
        if (attribute == DateFormat.Field.DAY_OF_MONTH) {
            return "day";
        }
        if (attribute == DateFormat.Field.HOUR0 || attribute == DateFormat.Field.HOUR1 || attribute == DateFormat.Field.HOUR_OF_DAY0 || attribute == DateFormat.Field.HOUR_OF_DAY1) {
            return "hour";
        }
        if (attribute == DateFormat.Field.MINUTE) {
            return "minute";
        }
        if (attribute == DateFormat.Field.SECOND) {
            return "second";
        }
        if (attribute == DateFormat.Field.TIME_ZONE) {
            return "timeZoneName";
        }
        if (attribute == DateFormat.Field.AM_PM) {
            return "dayPeriod";
        }
        if (attribute.toString().equals("android.icu.text.DateFormat$Field(related year)")) {
            return "relatedYear";
        }
        return "literal";
    }

    @Override // com.facebook.hermes.intl.IPlatformDateTimeFormatter
    public AttributedCharacterIterator formatToParts(double d) {
        return this.mDateFormat.formatToCharacterIterator(Double.valueOf(d));
    }

    @Override // com.facebook.hermes.intl.IPlatformDateTimeFormatter
    public String getDefaultCalendarName(ILocaleObject<?> iLocaleObject) throws JSRangeErrorException {
        return UnicodeExtensionKeys.resolveCalendarAlias(DateFormat.getDateInstance(3, (ULocale) iLocaleObject.getLocale()).getCalendar().getType());
    }

    private static class PatternUtils {
        private PatternUtils() {
        }

        public static String getPatternWithoutLiterals(String str) {
            StringBuilder sb = new StringBuilder();
            boolean z = false;
            for (int i = 0; i < str.length(); i++) {
                char cCharAt = str.charAt(i);
                if (cCharAt == '\'') {
                    z = !z;
                } else if (!z && ((cCharAt >= 'A' && cCharAt <= 'Z') || (cCharAt >= 'a' && cCharAt <= 'z'))) {
                    sb.append(str.charAt(i));
                }
            }
            return sb.toString();
        }
    }

    @Override // com.facebook.hermes.intl.IPlatformDateTimeFormatter
    public IPlatformDateTimeFormatter.HourCycle getDefaultHourCycle(ILocaleObject<?> iLocaleObject) throws JSRangeErrorException {
        IPlatformDateTimeFormatter.HourCycle hourCycle;
        try {
            String patternWithoutLiterals = PatternUtils.getPatternWithoutLiterals(((SimpleDateFormat) DateFormat.getTimeInstance(0, (ULocale) iLocaleObject.getLocale())).toPattern());
            if (patternWithoutLiterals.contains(String.valueOf('h'))) {
                hourCycle = IPlatformDateTimeFormatter.HourCycle.H12;
            } else if (patternWithoutLiterals.contains(String.valueOf('K'))) {
                hourCycle = IPlatformDateTimeFormatter.HourCycle.H11;
            } else if (patternWithoutLiterals.contains(String.valueOf('H'))) {
                hourCycle = IPlatformDateTimeFormatter.HourCycle.H23;
            } else {
                hourCycle = IPlatformDateTimeFormatter.HourCycle.H24;
            }
            return hourCycle;
        } catch (ClassCastException unused) {
            return IPlatformDateTimeFormatter.HourCycle.H24;
        }
    }

    @Override // com.facebook.hermes.intl.IPlatformDateTimeFormatter
    public String getDefaultTimeZone(ILocaleObject<?> iLocaleObject) throws JSRangeErrorException {
        return Calendar.getInstance((ULocale) iLocaleObject.getLocale()).getTimeZone().getID();
    }

    @Override // com.facebook.hermes.intl.IPlatformDateTimeFormatter
    public String getDefaultNumberingSystem(ILocaleObject<?> iLocaleObject) throws JSRangeErrorException {
        return NumberingSystem.getInstance((ULocale) iLocaleObject.getLocale()).getName();
    }

    static int toICUDateStyle(IPlatformDateTimeFormatter.DateStyle dateStyle) throws JSRangeErrorException {
        int i = AnonymousClass1.$SwitchMap$com$facebook$hermes$intl$IPlatformDateTimeFormatter$DateStyle[dateStyle.ordinal()];
        if (i == 1) {
            return 0;
        }
        if (i == 2) {
            return 1;
        }
        if (i == 3) {
            return 2;
        }
        if (i == 4) {
            return 3;
        }
        throw new JSRangeErrorException("Invalid DateStyle: " + dateStyle.toString());
    }

    /* renamed from: com.facebook.hermes.intl.PlatformDateTimeFormatterICU$1, reason: invalid class name */
    static /* synthetic */ class AnonymousClass1 {
        static final /* synthetic */ int[] $SwitchMap$com$facebook$hermes$intl$IPlatformDateTimeFormatter$DateStyle;
        static final /* synthetic */ int[] $SwitchMap$com$facebook$hermes$intl$IPlatformDateTimeFormatter$TimeStyle;

        static {
            int[] iArr = new int[IPlatformDateTimeFormatter.TimeStyle.values().length];
            $SwitchMap$com$facebook$hermes$intl$IPlatformDateTimeFormatter$TimeStyle = iArr;
            try {
                iArr[IPlatformDateTimeFormatter.TimeStyle.FULL.ordinal()] = 1;
            } catch (NoSuchFieldError unused) {
            }
            try {
                $SwitchMap$com$facebook$hermes$intl$IPlatformDateTimeFormatter$TimeStyle[IPlatformDateTimeFormatter.TimeStyle.LONG.ordinal()] = 2;
            } catch (NoSuchFieldError unused2) {
            }
            try {
                $SwitchMap$com$facebook$hermes$intl$IPlatformDateTimeFormatter$TimeStyle[IPlatformDateTimeFormatter.TimeStyle.MEDIUM.ordinal()] = 3;
            } catch (NoSuchFieldError unused3) {
            }
            try {
                $SwitchMap$com$facebook$hermes$intl$IPlatformDateTimeFormatter$TimeStyle[IPlatformDateTimeFormatter.TimeStyle.SHORT.ordinal()] = 4;
            } catch (NoSuchFieldError unused4) {
            }
            try {
                $SwitchMap$com$facebook$hermes$intl$IPlatformDateTimeFormatter$TimeStyle[IPlatformDateTimeFormatter.TimeStyle.UNDEFINED.ordinal()] = 5;
            } catch (NoSuchFieldError unused5) {
            }
            int[] iArr2 = new int[IPlatformDateTimeFormatter.DateStyle.values().length];
            $SwitchMap$com$facebook$hermes$intl$IPlatformDateTimeFormatter$DateStyle = iArr2;
            try {
                iArr2[IPlatformDateTimeFormatter.DateStyle.FULL.ordinal()] = 1;
            } catch (NoSuchFieldError unused6) {
            }
            try {
                $SwitchMap$com$facebook$hermes$intl$IPlatformDateTimeFormatter$DateStyle[IPlatformDateTimeFormatter.DateStyle.LONG.ordinal()] = 2;
            } catch (NoSuchFieldError unused7) {
            }
            try {
                $SwitchMap$com$facebook$hermes$intl$IPlatformDateTimeFormatter$DateStyle[IPlatformDateTimeFormatter.DateStyle.MEDIUM.ordinal()] = 3;
            } catch (NoSuchFieldError unused8) {
            }
            try {
                $SwitchMap$com$facebook$hermes$intl$IPlatformDateTimeFormatter$DateStyle[IPlatformDateTimeFormatter.DateStyle.SHORT.ordinal()] = 4;
            } catch (NoSuchFieldError unused9) {
            }
            try {
                $SwitchMap$com$facebook$hermes$intl$IPlatformDateTimeFormatter$DateStyle[IPlatformDateTimeFormatter.DateStyle.UNDEFINED.ordinal()] = 5;
            } catch (NoSuchFieldError unused10) {
            }
        }
    }

    static int toICUTimeStyle(IPlatformDateTimeFormatter.TimeStyle timeStyle) throws JSRangeErrorException {
        int i = AnonymousClass1.$SwitchMap$com$facebook$hermes$intl$IPlatformDateTimeFormatter$TimeStyle[timeStyle.ordinal()];
        if (i == 1) {
            return 0;
        }
        if (i == 2) {
            return 1;
        }
        if (i == 3) {
            return 2;
        }
        if (i == 4) {
            return 3;
        }
        throw new JSRangeErrorException("Invalid DateStyle: " + timeStyle.toString());
    }

    private static void replaceChars(StringBuilder sb, String str, String str2) {
        int iIndexOf = sb.indexOf(str);
        if (iIndexOf != -1) {
            sb.replace(iIndexOf, str.length() + iIndexOf, str2);
        }
    }

    private static String getPatternForStyle(ILocaleObject<?> iLocaleObject, IPlatformDateTimeFormatter.DateStyle dateStyle, IPlatformDateTimeFormatter.TimeStyle timeStyle) throws JSRangeErrorException {
        if (dateStyle == IPlatformDateTimeFormatter.DateStyle.UNDEFINED) {
            return ((SimpleDateFormat) DateFormat.getTimeInstance(toICUTimeStyle(timeStyle), (ULocale) iLocaleObject.getLocale())).toLocalizedPattern();
        }
        if (timeStyle == IPlatformDateTimeFormatter.TimeStyle.UNDEFINED) {
            return ((SimpleDateFormat) DateFormat.getDateInstance(toICUDateStyle(dateStyle), (ULocale) iLocaleObject.getLocale())).toLocalizedPattern();
        }
        return ((SimpleDateFormat) DateFormat.getDateTimeInstance(toICUDateStyle(dateStyle), toICUTimeStyle(timeStyle), (ULocale) iLocaleObject.getLocale())).toLocalizedPattern();
    }

    private static void replacePatternChars(StringBuilder sb, char[] cArr, char c) {
        for (int i = 0; i < sb.length(); i++) {
            int length = cArr.length;
            int i2 = 0;
            while (true) {
                if (i2 < length) {
                    if (sb.charAt(i) == cArr[i2]) {
                        sb.setCharAt(i, c);
                        break;
                    }
                    i2++;
                }
            }
        }
    }

    private static String getSkeleton(ILocaleObject<?> iLocaleObject, IPlatformDateTimeFormatter.WeekDay weekDay, IPlatformDateTimeFormatter.Era era, IPlatformDateTimeFormatter.Year year, IPlatformDateTimeFormatter.Month month, IPlatformDateTimeFormatter.Day day, IPlatformDateTimeFormatter.Hour hour, IPlatformDateTimeFormatter.Minute minute, IPlatformDateTimeFormatter.Second second, IPlatformDateTimeFormatter.TimeZoneName timeZoneName, IPlatformDateTimeFormatter.HourCycle hourCycle, IPlatformDateTimeFormatter.DateStyle dateStyle, IPlatformDateTimeFormatter.TimeStyle timeStyle, Object obj) throws JSRangeErrorException {
        StringBuilder sb = new StringBuilder();
        if (dateStyle != IPlatformDateTimeFormatter.DateStyle.UNDEFINED || timeStyle != IPlatformDateTimeFormatter.TimeStyle.UNDEFINED) {
            sb.append(getPatternForStyle(iLocaleObject, dateStyle, timeStyle));
            HashMap<String, String> unicodeExtensions = iLocaleObject.getUnicodeExtensions();
            if (unicodeExtensions.containsKey("hc")) {
                String str = unicodeExtensions.get("hc");
                if (str == LocalePreferences.HourCycle.H11 || str == LocalePreferences.HourCycle.H12) {
                    replacePatternChars(sb, new char[]{'H', 'K', 'k'}, 'h');
                } else if (str == LocalePreferences.HourCycle.H23 || str == LocalePreferences.HourCycle.H24) {
                    replacePatternChars(sb, new char[]{'h', 'H', 'K'}, 'k');
                }
            }
            if (hourCycle == IPlatformDateTimeFormatter.HourCycle.H11 || hourCycle == IPlatformDateTimeFormatter.HourCycle.H12) {
                replacePatternChars(sb, new char[]{'H', 'K', 'k'}, 'h');
            } else if (hourCycle == IPlatformDateTimeFormatter.HourCycle.H23 || hourCycle == IPlatformDateTimeFormatter.HourCycle.H24) {
                replacePatternChars(sb, new char[]{'h', 'H', 'K'}, 'k');
            }
            if (!JSObjects.isUndefined(obj) && !JSObjects.isNull(obj)) {
                if (JSObjects.getJavaBoolean(obj)) {
                    replacePatternChars(sb, new char[]{'H', 'K', 'k'}, 'h');
                } else {
                    replacePatternChars(sb, new char[]{'h', 'H', 'K'}, 'k');
                }
            }
        } else {
            sb.append(weekDay.getSkeleonSymbol());
            sb.append(era.getSkeleonSymbol());
            sb.append(year.getSkeleonSymbol());
            sb.append(month.getSkeleonSymbol());
            sb.append(day.getSkeleonSymbol());
            if (hourCycle == IPlatformDateTimeFormatter.HourCycle.H11 || hourCycle == IPlatformDateTimeFormatter.HourCycle.H12) {
                sb.append(hour.getSkeleonSymbol12());
            } else {
                sb.append(hour.getSkeleonSymbol24());
            }
            sb.append(minute.getSkeleonSymbol());
            sb.append(second.getSkeleonSymbol());
            sb.append(timeZoneName.getSkeleonSymbol());
        }
        return sb.toString();
    }

    @Override // com.facebook.hermes.intl.IPlatformDateTimeFormatter
    public void configure(ILocaleObject<?> iLocaleObject, String str, String str2, IPlatformDateTimeFormatter.FormatMatcher formatMatcher, IPlatformDateTimeFormatter.WeekDay weekDay, IPlatformDateTimeFormatter.Era era, IPlatformDateTimeFormatter.Year year, IPlatformDateTimeFormatter.Month month, IPlatformDateTimeFormatter.Day day, IPlatformDateTimeFormatter.Hour hour, IPlatformDateTimeFormatter.Minute minute, IPlatformDateTimeFormatter.Second second, IPlatformDateTimeFormatter.TimeZoneName timeZoneName, IPlatformDateTimeFormatter.HourCycle hourCycle, Object obj, IPlatformDateTimeFormatter.DateStyle dateStyle, IPlatformDateTimeFormatter.TimeStyle timeStyle, Object obj2) throws JSRangeErrorException {
        Calendar calendar;
        String skeleton = getSkeleton(iLocaleObject, weekDay, era, year, month, day, hour, minute, second, timeZoneName, hourCycle, dateStyle, timeStyle, obj2);
        if (str.isEmpty()) {
            calendar = null;
        } else {
            ArrayList<String> arrayList = new ArrayList<>();
            arrayList.add(JSObjects.getJavaString(str));
            ILocaleObject<?> iLocaleObjectCloneObject = iLocaleObject.cloneObject();
            iLocaleObjectCloneObject.setUnicodeExtensions("ca", arrayList);
            calendar = Calendar.getInstance((ULocale) iLocaleObjectCloneObject.getLocale());
        }
        if (!str2.isEmpty()) {
            try {
                if (NumberingSystem.getInstanceByName(JSObjects.getJavaString(str2)) == null) {
                    throw new JSRangeErrorException("Invalid numbering system: " + str2);
                }
                ArrayList<String> arrayList2 = new ArrayList<>();
                arrayList2.add(JSObjects.getJavaString(str2));
                iLocaleObject.setUnicodeExtensions("nu", arrayList2);
            } catch (RuntimeException unused) {
                throw new JSRangeErrorException("Invalid numbering system: " + str2);
            }
        }
        if (calendar != null) {
            this.mDateFormat = DateFormat.getPatternInstance(calendar, skeleton, (ULocale) iLocaleObject.getLocale());
        } else {
            this.mDateFormat = DateFormat.getPatternInstance(skeleton, (ULocale) iLocaleObject.getLocale());
        }
        if (JSObjects.isUndefined(obj) || JSObjects.isNull(obj)) {
            return;
        }
        this.mDateFormat.setTimeZone(TimeZone.getTimeZone(JSObjects.getJavaString(obj)));
    }

    @Override // com.facebook.hermes.intl.IPlatformDateTimeFormatter
    public String[] getAvailableLocales() {
        ArrayList arrayList = new ArrayList();
        for (ULocale uLocale : ULocale.getAvailableLocales()) {
            arrayList.add(uLocale.toLanguageTag());
        }
        return (String[]) arrayList.toArray(new String[arrayList.size()]);
    }

    PlatformDateTimeFormatterICU() {
    }
}
