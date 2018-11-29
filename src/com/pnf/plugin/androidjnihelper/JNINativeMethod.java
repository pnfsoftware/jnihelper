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

import java.util.concurrent.atomic.AtomicLong;

import com.pnfsoftware.jeb.core.exceptions.JebRuntimeException;
import com.pnfsoftware.jeb.core.units.INativeCodeUnit;
import com.pnfsoftware.jeb.core.units.code.asm.memory.IVirtualMemory;
import com.pnfsoftware.jeb.core.units.code.asm.memory.MemoryException;
import com.pnfsoftware.jeb.util.format.Strings;

/**
 * @author Cedric Lucas
 *
 */
class JNINativeMethod {
    long ptrName, ptrSignature, ptrFnPtr; // array of pointers to name, signature and jni function
    String name;
    String signature;
    long fnPtr;

    public JNINativeMethod(String name, String signature, long fnPtr, long ptrName, long ptrSignature, long ptrFnPtr) {
        this.name = name;
        this.signature = signature;
        this.fnPtr = fnPtr;
        this.ptrName = ptrName;
        this.ptrSignature = ptrSignature;
        this.ptrFnPtr = ptrFnPtr;
    }

    @Override
    public String toString() {
        return "JNINativeMethod [" + name + signature + ", @" + Long.toHexString(fnPtr) + "]";
    }

    public static JNINativeMethod buildJNIFromMemPointer(INativeCodeUnit<?> codeUnit, IVirtualMemory vm,
            AtomicLong ptrMutMethods) {
        long ptrMethodsInit = ptrMutMethods.get();
        long ptrName = ptrMethodsInit;
        try {
            long dataAddress = vm.readPointer(ptrName);
            String name = DynamicJNIDetectionPlugin.readStringUTF8(vm, dataAddress);
            if(Strings.isBlank(name)) {
                ptrMutMethods.set(ptrMethodsInit + 3 * vm.getSpaceBits() / 8);
                return null;
            }
            long ptrSignature = ptrName + vm.getSpaceBits() / 8;
            dataAddress = vm.readPointer(ptrSignature);
            String signature = DynamicJNIDetectionPlugin.readStringUTF8(vm, dataAddress);
            if(!signature.startsWith("(") || !signature.contains(")")) {
                // false positive
                ptrMutMethods.set(ptrMethodsInit + 3 * vm.getSpaceBits() / 8);
                return null;
            }
            long ptrFnPtr = ptrSignature + vm.getSpaceBits() / 8;
            long fnPtr = vm.readPointer(ptrFnPtr);
            if(!codeUnit.getCodeAnalyzer().getAnalysisRanges().contains(fnPtr)) {
                String message = Strings.f("Dynamic Jni Pointer in %s @%xh is out of analysis range for Jni table @%xh",
                        codeUnit.getParent().getName(), fnPtr, ptrMethodsInit);
                DynamicJNIDetectionPlugin.logger.warn(message);
                // warn JEB for investigation (if enabled in parameters)
                DynamicJNIDetectionPlugin.logger.catchingSilent(new JebRuntimeException(message));
            }
            JNINativeMethod jni = new JNINativeMethod(name, signature, fnPtr, ptrName, ptrSignature, ptrFnPtr);
            ptrMutMethods.set(ptrFnPtr + vm.getSpaceBits() / 8);
            return jni;
        }
        catch(MemoryException e) {
            DynamicJNIDetectionPlugin.logger.error("Can not parse JNINativeMethod @%xh", ptrMethodsInit);
            // attempt to jump to next pointer
        }
        ptrMutMethods.set(ptrMethodsInit + 3 * vm.getSpaceBits() / 8);
        return null;
    }
}