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

import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.concurrent.atomic.AtomicLong;

import com.pnfsoftware.jeb.core.units.INativeCodeUnit;
import com.pnfsoftware.jeb.core.units.code.android.dex.IDexMethod;
import com.pnfsoftware.jeb.core.units.code.asm.analyzer.IReference;
import com.pnfsoftware.jeb.core.units.code.asm.items.INativeStringItem;
import com.pnfsoftware.jeb.core.units.code.asm.memory.IVirtualMemory;
import com.pnfsoftware.jeb.core.units.codeobject.ISymbolInformation;
import com.pnfsoftware.jeb.util.logging.GlobalLog;
import com.pnfsoftware.jeb.util.logging.ILogger;

/**
 * Search for argument string in image strings. Attempt to retrieve xrefs to determine pointer to
 * method and function address. This heuristic is powerful when function names are obfuscated with
 * a/aa... because method name strings would be too short to be created.
 * 
 * @author Cedric Lucas
 *
 */
public class DynamicJNIDetectionHeurFromSignature implements IDynamicJNIDetectionHeuritic {
    private static final ILogger logger = GlobalLog.getLogger(DynamicJNIDetectionHeurFromSignature.class);

    @Override
    public List<JNINativeMethod> determine(INativeCodeUnit<?> codeUnit, List<IDexMethod> nativeMethods,
            ISymbolInformation onload) {
        List<JNINativeMethod> registered = new ArrayList<>();
        for(INativeStringItem str: codeUnit.getStrings()) {
            String sig = str.getValue();
            if(sig.startsWith("(") && sig.contains(")")) {
                logger.info("JNI matching arg %s found @%Xh", str.getValue(), str.getBegin());
                // get xref from string, this is generally the pointer array+1
                Set<? extends IReference> xrefs = codeUnit.getCodeModel().getReferenceManager()
                        .getReferencesToTarget(str.getBegin());
                if(xrefs != null && !xrefs.isEmpty()) {
                    // can have same signature shared across
                    for(IReference xref: xrefs) {
                        IVirtualMemory vm = codeUnit.getMemory();
                        AtomicLong ptrMethods = new AtomicLong(xref.getAddress() - vm.getSpaceBits() / 8);
                        if(ptrMethods.longValue() < 0) {
                            continue;
                        }
                        JNINativeMethod jni = JNINativeMethod.buildJNIFromMemPointer(codeUnit, vm, ptrMethods);
                        if(jni != null) {
                            // validate that method name matches an existing JNI method name
                            for(IDexMethod m: nativeMethods) {
                                if(m.getName(true).equals(jni.name)) {
                                    registered.add(jni);
                                    break;
                                }
                            }
                        }
                    }
                }
            }
        }
        return registered;
    }
}
