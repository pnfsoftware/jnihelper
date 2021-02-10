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
 * Search for related string from dex native functions names in image strings. Attempt to retrieve
 * xrefs to determine pointer to signature and function address.
 * 
 * @author Cedric Lucas
 *
 */
public class DynamicJNIDetectionHeurFromMethodName implements IDynamicJNIDetectionHeuritic {
    private static final ILogger logger = GlobalLog.getLogger(DynamicJNIDetectionHeurFromMethodName.class);

    @Override
    public List<JNINativeMethod> determine(INativeCodeUnit<?> codeUnit, List<IDexMethod> nativeMethods,
            ISymbolInformation onload) {
        List<JNINativeMethod> registered = new ArrayList<>();
        for(INativeStringItem str: codeUnit.getStrings()) {
            for(IDexMethod m: nativeMethods) {
                if(m.getName(true).equals(str.getValue())) {
                    logger.info("JNI matching method name %s found @%Xh", str.getValue(), str.getBegin());
                    // get xref from string, this is generally the pointer array
                    Set<? extends IReference> xrefs = codeUnit.getCodeModel().getReferenceManager()
                            .getReferencesTo(str.getBegin());
                    if(xrefs != null && !xrefs.isEmpty()) {
                        // can have same name shared across (for example, with different signature)
                        for(IReference xref: xrefs) {
                            if(xref.getTo().isInternalAddress()) {
                                AtomicLong ptrMethods = new AtomicLong(xref.getTo().getInternalAddress());
                                IVirtualMemory vm = codeUnit.getMemory();
                                // read one by one
                                JNINativeMethod jni = JNINativeMethod.buildJNIFromMemPointer(codeUnit, vm, ptrMethods);
                                if(jni != null) {
                                    registered.add(jni);
                                }
                            }
                        }
                        break; // build potential jni, do not match signature here. Once method name is matched, no need to check others
                    } // else, should check any caller? too dangerous
                }
            }
        }
        return registered;
    }
}
