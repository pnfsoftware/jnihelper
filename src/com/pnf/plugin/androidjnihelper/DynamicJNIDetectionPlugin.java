/*
 * JEB Copyright PNF Software, Inc.
 * 
 *     https://www.pnfsoftware.com
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *     http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.pnf.plugin.androidjnihelper;

import java.io.ByteArrayOutputStream;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import com.pnfsoftware.jeb.core.AbstractEnginesPlugin;
import com.pnfsoftware.jeb.core.IEnginesContext;
import com.pnfsoftware.jeb.core.ILiveArtifact;
import com.pnfsoftware.jeb.core.IPluginInformation;
import com.pnfsoftware.jeb.core.IRuntimeProject;
import com.pnfsoftware.jeb.core.JebCoreService;
import com.pnfsoftware.jeb.core.PluginInformation;
import com.pnfsoftware.jeb.core.Version;
import com.pnfsoftware.jeb.core.units.IInteractiveUnit;
import com.pnfsoftware.jeb.core.units.INativeCodeUnit;
import com.pnfsoftware.jeb.core.units.IUnit;
import com.pnfsoftware.jeb.core.units.code.android.DexUtil;
import com.pnfsoftware.jeb.core.units.code.android.IApkUnit;
import com.pnfsoftware.jeb.core.units.code.android.IDexUnit;
import com.pnfsoftware.jeb.core.units.code.android.IJniEndpoint;
import com.pnfsoftware.jeb.core.units.code.android.dex.IDexClass;
import com.pnfsoftware.jeb.core.units.code.android.dex.IDexMethod;
import com.pnfsoftware.jeb.core.units.code.asm.items.INativeItem;
import com.pnfsoftware.jeb.core.units.code.asm.items.INativeMethodItem;
import com.pnfsoftware.jeb.core.units.code.asm.memory.IVirtualMemory;
import com.pnfsoftware.jeb.core.units.code.asm.memory.MemoryException;
import com.pnfsoftware.jeb.core.units.code.asm.type.INativeType;
import com.pnfsoftware.jeb.core.units.codeobject.IELFUnit;
import com.pnfsoftware.jeb.core.units.codeobject.ISymbolInformation;
import com.pnfsoftware.jeb.util.format.Strings;
import com.pnfsoftware.jeb.util.logging.GlobalLog;
import com.pnfsoftware.jeb.util.logging.ILogger;

/**
 * There are currently two ways to call JNI from Java code:<br>
 * <ul>
 * <li>use the standard name "Java_&lt;fully qualified name>_methodName"</li>
 * <li>create dynamic bounds.</li>
 * </ul>
 * <p>
 * Since JEB already manages the standard JNI naming, this plugin will try to determine and bound
 * the dynamic JNI functions.
 * <p>
 * The dynamic initialization is done in the method <code>JNI_OnLoad<code>. This method will call
 * the RegisterNatives method which has 4 arguments (JNIEnv *env, jclass clazz, const
 * JNINativeMethod *methods, jint nMethods). So we must determine the 3rd and 4th arguments.
 * 
 * @author Cedric Lucas
 *
 */
public class DynamicJNIDetectionPlugin extends AbstractEnginesPlugin {
    static final ILogger logger = GlobalLog.getLogger(DynamicJNIDetectionPlugin.class);

    private JNIReport report;

    private IDynamicJNIDetectionHeuritic[] heuristics = { // list of heuristics used
            new DynamicJNIDetectionHeurRegisterNatives(), // EP JNI_OnLoad
            new DynamicJNIDetectionHeurFromMethodName(), // EP Method name strings
            new DynamicJNIDetectionHeurFromSignature(), // EP Signature
    };

    @Override
    public IPluginInformation getPluginInformation() {
        return new PluginInformation("Dynamic JNI Detection Plugin",
                "Heuristically discover dynamically loaded JNI function and enable JEB to use them (debug)",
                "PNF Software", Version.create(1, 0, 2), Version.create(3, 4, 0));
    }

    @Override
    public void execute(IEnginesContext context, Map<String, String> executionOptions) {
        try {
            report = new JNIReport();
            executeInternal(context, executionOptions);
        }
        catch(Exception e) {
            logger.error("An error occurred while executing the plugin");
            logger.catchingSilent(e);
            JebCoreService.notifySilentExceptionToClient(e);
        }
        finally {
            logger.info(report.getReport());
        }
    }

    private void executeInternal(IEnginesContext context, Map<String, String> executionOptions) {
        List<IApkUnit> apkUnits = getApkUnits(context);
        if(apkUnits.isEmpty()) {
            logger.info("No apk candidate can be found");
            return;
        }
        for(IApkUnit apk: apkUnits) {
            IUnit libs = apk.getLibrariesUnit();
            if(libs == null) {
                logger.info("Native libraries not found");
                continue;
            }

            List<IUnit> candidates = getCandidateAbis(libs);
            if(candidates == null || candidates.isEmpty()) {
                continue;
            }

            for(IUnit candidate: candidates) {
                List<IDexMethod> nativeMethods = getNativeMethods(apk.getDex());
                List<? extends IUnit> sos = candidate.getChildren();

                if(nativeMethods.isEmpty()) {
                    continue;
                }

                List<JNINativeMethod> allFunctions = new ArrayList<>();
                for(IUnit so: sos) {
                    if(so instanceof IELFUnit) {
                        // check for JNI_OnLoad method
                        IELFUnit elf = (IELFUnit)so;
                        logger.debug("Processing %s:%s", elf.getName(),
                                elf.getLoaderInformation().getTargetProcessor());
                        ISymbolInformation onload = null;
                        List<? extends ISymbolInformation> symbols = elf.getExportedSymbols();
                        for(ISymbolInformation sym: symbols) {
                            if(sym.getName().equals("JNI_OnLoad")) {
                                onload = sym;
                                break;
                            }
                        }
                        if(onload == null) {
                            // no JNI in this so
                            continue;
                        }
                        IUnit image = elf.getImageUnit();
                        if(!(image instanceof INativeCodeUnit<?>)) {
                            continue;
                        }
                        INativeCodeUnit<?> codeUnit = (INativeCodeUnit<?>)image;
                        if(!codeUnit.isProcessed()) {
                            codeUnit.process();
                        }
                        if(!codeUnit.isInitialAnalysisDone()) {
                            codeUnit.performInitialAnalysis();
                        }
                        // wait for process completed (can be performing background when user launch plugin)
                        while(!codeUnit.isAnalysisCompleted()) {
                            try {
                                Thread.sleep(1000);
                            }
                            catch(InterruptedException e) {
                                logger.catching(e);
                                break;
                            }
                        }

                        // heuristic1
                        for(IDynamicJNIDetectionHeuritic h: heuristics) {
                            List<JNINativeMethod> functions = h.determine(codeUnit, nativeMethods, onload);
                            allFunctions.addAll(functions);
                        }
                    } // else not an ELF?
                    else {
                        logger.error("Can not proceed with unit %s", so);
                    }
                }
                sanitize(allFunctions);
                for(JNINativeMethod jni: allFunctions) {
                    processJNIMethod(apk, nativeMethods, jni, candidate.getName());
                }

                // postprocess: Remove static method definitions
                // (can not delete them at beginning since dynamic definitions overwrite static ones)
                for(IUnit so: sos) {
                    if(so instanceof IELFUnit) {
                        IELFUnit elf = (IELFUnit)so;
                        List<? extends ISymbolInformation> symbols = elf.getExportedSymbols();
                        for(ISymbolInformation sym: symbols) {
                            if(sym.getName().startsWith("Java_")) {
                                for(int i = 0; i < nativeMethods.size(); i++) {
                                    IDexMethod m = nativeMethods.get(i);
                                    String sig = m.getSignature(true);
                                    String[] names = DexUtil.toJniName(sig);
                                    for(String name: names) {
                                        if(name.equals(sym.getName())) {
                                            logger.debug("Found static JNI method: %s", sym.getName());
                                            report.saveStaticMethod(apk, elf, sig, candidate.getName(), sym);
                                            nativeMethods.remove(i);
                                            break;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                if(!nativeMethods.isEmpty()) {
                    for(int i = 0; i < nativeMethods.size(); i++) {
                        IDexMethod m = nativeMethods.get(i);
                        String methodName = m.getSignature(true);
                        logger.debug("JNI method not found: %s", methodName);
                        report.saveMissingMethod(apk, methodName, candidate.getName());
                    }
                }
            }
        }
    }

    /**
     * Remove duplicates
     * 
     * @param functions
     */
    private void sanitize(List<JNINativeMethod> functions) {
        for(int i = 0; i < functions.size(); i++) {
            boolean removeAtEnd = false;
            JNINativeMethod elt1 = functions.get(i);
            for(int j = i + 1; j < functions.size(); j++) {
                JNINativeMethod elt2 = functions.get(j);
                if(elt1.name.equals(elt2.name) && elt1.signature.equals(elt2.signature)) {
                    functions.remove(j);
                    j--;
                    // same code Unit and address => remove duplicate
                    if(elt1.codeUnit != elt2.codeUnit || elt1.fnPtr != elt2.fnPtr) {
                        // same native method locates several places
                        removeAtEnd = true;
                    }
                }
            }
            if(removeAtEnd) {
                logger.error("Found duplicate native method references for %s", elt1.name);
                functions.remove(i);
                i--;
            }
        }
    }

    private List<IDexMethod> getNativeMethods(IDexUnit dex) {
        List<IDexMethod> natives = new ArrayList<>();
        for(IDexClass c: dex.getClasses()) {
            List<? extends IDexMethod> methods = c.getMethods();
            if(methods != null) {
                for(IDexMethod m: c.getMethods()) {
                    if((m.getGenericFlags() & IDexMethod.FLAG_NATIVE) != 0) {
                        natives.add(m);
                    }
                }
            }
        }
        return natives;
    }

    /**
     * @param vm
     * @param ptrMethods
     * @return
     * @throws MemoryException
     */
    static String readStringUTF8(IVirtualMemory vm, long ptrMethods) throws MemoryException {
        byte[] buffer = new byte[512];
        //long readSize = 0;
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        boolean endCharDetected = false;
        do {
            int read = vm.read(ptrMethods, buffer.length, buffer, 0);
            for(int i = 0; i < read; i++) {
                //readSize++;
                if(buffer[i] == 0) {
                    endCharDetected = true;
                    break;
                }
                bos.write(buffer[i]);
            }
        }
        while(!endCharDetected);
        return new String(bos.toByteArray(), Charset.forName("UTF-8"));
    }

    private List<IUnit> getCandidateAbis(IUnit libs) {
        List<IUnit> candidates = new ArrayList<>();
        for(IUnit lib: libs.getChildren()) {
            if(lib.getName().contains("arm")) {
                candidates.add(lib);
            }
            else {
                // FIXME extend to x86, mips
            }
        }
        return candidates;
    }

    private List<IApkUnit> getApkUnits(IEnginesContext context) {
        // recursive: apk can embed other apks
        List<IApkUnit> apks = new ArrayList<>();
        for(IRuntimeProject prj: context.getProjects()) {
            for(ILiveArtifact art: prj.getLiveArtifacts()) {
                getApkUnits(art.getUnits(), apks);
            }
        }
        return apks;
    }

    private void getApkUnits(List<? extends IUnit> units, List<IApkUnit> apks) {
        if(units == null) {
            return;
        }
        for(IUnit unit: units) {
            if(unit instanceof IApkUnit) {
                apks.add((IApkUnit)unit);
            }
            getApkUnits(unit.getChildren(), apks);
        }
    }

    // ----------------------------- JNI processing -------------------------//

    protected boolean processJNIMethod(IApkUnit apk, List<IDexMethod> nativeMethods, JNINativeMethod jni,
            String libName) {
        logger.debug("JNI Method: %s %s %xh", jni.name, jni.signature, jni.fnPtr);
        boolean thumb = (jni.fnPtr & 1) != 0;
        String methodAddress = Long.toHexString(thumb ? jni.fnPtr - 1: jni.fnPtr) + "h";

        // add comment in Native code
        String newComment = Strings.f("JNI method Detected: %s %s", jni.name, jni.signature);
        appendComment(jni.codeUnit, methodAddress, newComment);

        // add comment in Dalvik
        IDexUnit dex = apk.getDex();
        IDexMethod m = getDexMethod(nativeMethods, jni);
        if(m == null) {
            logger.error("Can not define JNI method @%Xh", jni.fnPtr);
            return false;
        }
        IUnit elf = (IUnit)jni.codeUnit.getParent();
        newComment = Strings.f("%s is registered dynamically, it references native routine @%Xh in file %s/%s",
                jni.name, jni.fnPtr, elf.getParent().getName(), elf.getName());
        appendComment(dex, m.getAddress(), newComment);

        String signature = m.getSignature(true);
        List<IJniEndpoint> endpoints = apk.dynamic().getJniMethods(signature);
        boolean alreadyDefined = false;
        if(endpoints != null) {
            for(IJniEndpoint endpoint: endpoints) {
                if(!endpoint.isStatic()) {
                    if(endpoint.getUnit() == elf) {
                        alreadyDefined = true;
                        break;
                    }
                }
            }
        }
        if(!alreadyDefined) {
            apk.dynamic().registerDynamicJni(signature, elf, jni.fnPtr);
        }

        // define method at JNI address if nothing defined
        INativeItem item = jni.codeUnit.getItemObject(jni.codeUnit.getItemAtAddress(methodAddress));
        if(item == null || !(item instanceof INativeMethodItem)) {
            // define method
            jni.codeUnit.setRoutineAt(jni.fnPtr);
            item = jni.codeUnit.getItemObject(jni.codeUnit.getItemAtAddress(methodAddress));
            if(item == null || !(item instanceof INativeMethodItem)) {
                logger.error("Can not define JNI method @%Xh", jni.fnPtr);
                return true;
            }
        }

        // rename native method
        INativeMethodItem method = (INativeMethodItem)item;
        String oldMethodName = method.getName(true);
        String methodName = null;
        if(oldMethodName.startsWith("sub_") && !jni.name.startsWith("sub_")) {
            methodName = "__jni_" + jni.name + "_" + jni.signature;
            // validate that function name does not already exist
            if(jni.codeUnit.getMethod(methodName) == null) {
                method.setName(methodName);
                if(method.getName(true).startsWith("__jni_")) {
                    logger.debug("Method %s was renamed to %s", oldMethodName, methodName);
                }
            }
        }

        // define pointers
        INativeType dataType = jni.codeUnit.getTypeManager().getType("void*");
        if(dataType != null) {
            jni.codeUnit.setDataAt(jni.ptrName, dataType, "__jni_ptr_" + jni.name);
            jni.codeUnit.setDataTypeAt(jni.ptrSignature, dataType);
            jni.codeUnit.setDataTypeAt(jni.ptrFnPtr, dataType);
        }
        report.saveDynamicMethodMatch(apk, elf, signature, libName, jni, oldMethodName, methodName);
        return true;
    }

    private void appendComment(IInteractiveUnit unit, String address, String newComment) {
        String comment = unit.getComment(address);
        if(comment != null) {
            if(comment.contains(newComment)) {
                // already added (several run of plugin)
                newComment = comment;
            }
            else {
                newComment = comment + "\n" + newComment;
            }
        }
        unit.setComment(address, newComment);
    }

    private IDexMethod getDexMethod(List<IDexMethod> nativeMethods, JNINativeMethod jni) {
        for(int i = 0; i < nativeMethods.size(); i++) {
            IDexMethod m = nativeMethods.get(i);
            if(m.getName(true).equals(jni.name)) {
                String classSig = m.getSignature(true);
                int argStart = classSig.indexOf("(");
                if(argStart >= 0 && classSig.substring(argStart).equals(jni.signature)) {
                    nativeMethods.remove(m);
                    return m;
                }
            }
        }
        return null;
    }
}
