/*
 * JEB Copyright (c) PNF Software, Inc.
 * All rights reserved.
 * This file shall not be distributed or reused, in part or in whole.
 */
package com.pnf.plugin.androidjnihelper;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;
import java.util.TreeMap;

import com.pnfsoftware.jeb.core.units.IUnit;
import com.pnfsoftware.jeb.core.units.code.android.IApkUnit;
import com.pnfsoftware.jeb.core.units.codeobject.ISymbolInformation;
import com.pnfsoftware.jeb.util.format.Strings;

/**
 * JNI Report
 * 
 * @author Cedric Lucas
 *
 */
public class JNIReport {

    private static class ApkData {
        /** signature -> binding */
        Map<String, List<ApkBinding>> bindings = new TreeMap<>();

        public List<ApkBinding> getBindings(String signature) {
            List<ApkBinding> lines = bindings.get(signature);
            if(lines == null) {
                lines = new ArrayList<>();
                bindings.put(signature, lines);
            }
            return lines;
        }
    }

    private static class ApkBinding {
        private boolean dynamic;
        private String libName;
        private String elfName;
        private long nativePtr;
        private String oldMethodName;
        private String methodName;

        public ApkBinding(boolean dynamic, String libName, String elfName, long nativePtr, String oldMethodName,
                String methodName) {
            this.dynamic = dynamic;
            this.libName = libName;
            this.elfName = elfName;
            this.nativePtr = nativePtr;
            this.oldMethodName = oldMethodName;
            this.methodName = methodName;
        }

        public boolean isBindingFound() {
            return elfName != null;
        }

        @Override
        public String toString() {
            if(!isBindingFound()) {
                return libName + ": Can not fount JNI Endpoint";
            }
            return (dynamic ? "Dynamic": "Static") + " JNI detected in " + libName + "/" + elfName + " @"
                    + Long.toHexString(nativePtr) + "h. Method "
                    + (methodName != null ? "was renamed from " + oldMethodName + " to " + methodName
                            : "name is " + oldMethodName);
        }

    }

    private Map<String, ApkData> report = new HashMap<>();

    private ApkData getApkData(IApkUnit apk) {
        ApkData data = report.get(apk.getName());
        if(data == null) {
            data = new ApkData();
            report.put(apk.getName(), data);
        }
        return data;
    }

    public void saveDynamicMethodMatch(IApkUnit apk, IUnit elf, String signature, String libName, JNINativeMethod jni,
            String oldMethodName, String methodName) {
        List<ApkBinding> lines = getApkData(apk).getBindings(signature);
        lines.add(new ApkBinding(true, libName, elf.getName(), jni.fnPtr, oldMethodName, methodName));
    }

    public void saveStaticMethod(IApkUnit apk, IUnit elf, String signature, String libName, ISymbolInformation sym) {
        List<ApkBinding> lines = getApkData(apk).getBindings(signature);
        lines.add(new ApkBinding(false, libName, elf.getName(), sym.getRelativeAddress(), sym.getName(), null));
    }

    public void saveMissingMethod(IApkUnit apk, String signature, String libName) {
        List<ApkBinding> lines = getApkData(apk).getBindings(signature);
        lines.add(new ApkBinding(true, libName, null, 0L, null, null));
    }

    public String getReport() {
        StringBuilder stb = new StringBuilder();

        stb.append("JNI Method summary\n");
        stb.append("------------------\n");
        if(report.isEmpty()) {
            stb.append("No JNI Method found!");
            return stb.toString();
        }
        int totalNativeMethods = 0;
        Map<String, Integer> dynamicNativeMethodsPerLib = new HashMap<>();
        Map<String, Integer> staticNativeMethodsPerLib = new HashMap<>();
        for(Entry<String, ApkData> reportEntry: report.entrySet()) {
            stb.append(reportEntry.getKey()).append('\n');
            int maxLength = 20;
            for(Entry<String, List<ApkBinding>> apkBindings: reportEntry.getValue().bindings.entrySet()) {
                if (apkBindings.getKey().length() > maxLength) {
                    maxLength = apkBindings.getKey().length();
                    if(maxLength > 90) {
                        maxLength = 90;
                        break;
                    }
                }
            }
            for(Entry<String, List<ApkBinding>> apkBindings: reportEntry.getValue().bindings.entrySet()) {
                totalNativeMethods++;
                if(isBindingFound(apkBindings.getValue())) {
                    for(ApkBinding line: apkBindings.getValue()) {
                        int pad = maxLength - apkBindings.getKey().length();
                        stb.append(apkBindings.getKey()).append(Strings.pad(' ', pad >= 0 ? pad: Math.abs(pad) % 10))
                                .append(" --> ").append(line).append('\n');
                        increment(line.dynamic ? dynamicNativeMethodsPerLib: staticNativeMethodsPerLib, line.libName);
                    }
                }
                else {
                    stb.append("No binding found for ").append(apkBindings.getKey()).append('\n');
                }
            }
        }
        stb.append("------------------\n");
        stb.append("Found a total of ").append(totalNativeMethods).append(" native methods.\n");
        Set<String>libs = new HashSet<>();
        libs.addAll(dynamicNativeMethodsPerLib.keySet());
        libs.addAll(staticNativeMethodsPerLib.keySet());
        for (String lib : libs) {
            stb.append("Found ").append(dynamicNativeMethodsPerLib.get(lib)).append(" dynamic method(s) and ")
                    .append(staticNativeMethodsPerLib.get(lib)).append(" static method(s) for ").append(lib)
                    .append(".\n");
        }
        stb.append("------------------\n");
        return stb.toString();
    }

    private void increment(Map<String, Integer> map, String libName) {
        Integer res = map.get(libName);
        if(res == null) {
            res = 1;
        }
        else {
            res = res + 1;
        }
        map.put(libName, res);
    }

    private boolean isBindingFound(List<ApkBinding> bs) {
        for(ApkBinding b: bs) {
            if(b.isBindingFound()) {
                return true;
            }
        }
        return false;
    }
}
