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
import java.util.concurrent.atomic.AtomicLong;

import com.pnfsoftware.jeb.core.units.INativeCodeUnit;
import com.pnfsoftware.jeb.core.units.code.EntryPointDescription;
import com.pnfsoftware.jeb.core.units.code.IDecompilerUnit;
import com.pnfsoftware.jeb.core.units.code.IFlowInformation;
import com.pnfsoftware.jeb.core.units.code.IInstruction;
import com.pnfsoftware.jeb.core.units.code.android.dex.IDexMethod;
import com.pnfsoftware.jeb.core.units.code.asm.cfg.BasicBlock;
import com.pnfsoftware.jeb.core.units.code.asm.decompiler.IEConverter;
import com.pnfsoftware.jeb.core.units.code.asm.decompiler.IERoutineContext;
import com.pnfsoftware.jeb.core.units.code.asm.decompiler.INativeDecompilerUnit;
import com.pnfsoftware.jeb.core.units.code.asm.decompiler.ir.EUtil;
import com.pnfsoftware.jeb.core.units.code.asm.decompiler.ir.IEGeneric;
import com.pnfsoftware.jeb.core.units.code.asm.decompiler.ir.IEState;
import com.pnfsoftware.jeb.core.units.code.asm.decompiler.ir.IEStatement;
import com.pnfsoftware.jeb.core.units.code.asm.decompiler.ir.IdRanges;
import com.pnfsoftware.jeb.core.units.code.asm.items.INativeMethodItem;
import com.pnfsoftware.jeb.core.units.code.asm.memory.IVirtualMemory;
import com.pnfsoftware.jeb.core.units.codeobject.ISymbolInformation;
import com.pnfsoftware.jeb.core.util.DecompilerHelper;
import com.pnfsoftware.jeb.util.format.Formatter;
import com.pnfsoftware.jeb.util.logging.GlobalLog;
import com.pnfsoftware.jeb.util.logging.ILogger;

/**
 * First, identifies the JNI_OnLoad method and look for RegisterNatives calls. Once identified,
 * extract the JNI parameters. If this heuristic is successful, it is perfectly sure that result are
 * real JNI methods (except if several classpath names exist for same method signature - would be
 * mostly related to obfuscation).
 * 
 * @author Cedric Lucas
 *
 */
public class DynamicJNIDetectionHeurRegisterNatives implements IDynamicJNIDetectionHeuritic {
    private static final ILogger logger = GlobalLog.getLogger(DynamicJNIDetectionHeurRegisterNatives.class);

    @Override
    public List<JNINativeMethod> determine(INativeCodeUnit<?> codeUnit, List<IDexMethod> nativeMethods,
            ISymbolInformation onload) {
        List<JNINativeMethod> registered = new ArrayList<>();

        // Retrieve method JNI_OnLoad
        EntryPointDescription ep = codeUnit.getProcessor()
                .createEntryPoint(codeUnit.getVirtualImageBase() + onload.getSymbolRelativeAddress());
        INativeMethodItem method = codeUnit.getInternalMethod(ep.getAddress(), true);
        if(method == null) {
            // second chance, look for method name
            method = codeUnit.getMethod("JNI_OnLoad");
            if(method == null) {
                return registered;
            }
        }
        for(BasicBlock<?> block: method.getData().getCFG().getBlocks()) {
            // look for routine call to RegisterNatives
            if(isBlockCallsRegisterNatives(codeUnit, block)) {

                // determine params R2,R3 (JNINativeMethod)
                IDecompilerUnit decompiler = DecompilerHelper.getDecompiler(codeUnit);
                if(decompiler != null && decompiler instanceof INativeDecompilerUnit<?>) {
                    IEConverter<?> conv = ((INativeDecompilerUnit<?>)decompiler).getConverter();

                    IERoutineContext ctx = null;
                    List<IEStatement> r = null;
                    try {
                        ctx = conv.convert(method);
                        BasicBlock<IEStatement> bb = ctx.getCfg()
                                .getBlockAt(ctx.convertNativeAddress(block.getFirstAddress()));
                        r = bb.getInstructions();
                    }
                    catch(Exception e) {
                        logger.catching(e);
                    }
                    if(ctx == null || r == null) {
                        return registered;
                    }

                    // targets are defined by ARM variables R2, R3. same for ARM64 X2, X3
                    IEGeneric[] targets = {conv.getRegisterVariableFromNativeRegisterId(2),
                            conv.getRegisterVariableFromNativeRegisterId(3)};
                    if(EUtil.resolveExpressionsBackward("RegisterNatives", conv, r, targets)) {
                        if(!hasVariable(targets[0]) && !hasVariable(targets[1])) {
                            IEState state = ctx.getGlobalContext().buildState();
                            IVirtualMemory vm = codeUnit.getMemory();
                            state.setMemory(vm);
                            int nMethods;
                            long ptrMethods0;
                            try {
                                nMethods = (int)targets[1].evaluateUnsignedLong(state);
                                logger.i("Number of methods: %d", nMethods);
                                ptrMethods0 = (int)targets[0].evaluateUnsignedLong(state);
                                logger.i("Pointer to methods: %xh", ptrMethods0);
                            }
                            catch(Exception e) {
                                logger.error("Can not determine parameters of RegisterNatives method in block @%xh",
                                        block.getFirstAddress());
                                continue;
                            }
                            AtomicLong ptrMethods = new AtomicLong(ptrMethods0);
                            for(int j = 0; j < nMethods; j++) {
                                JNINativeMethod jni = JNINativeMethod.buildJNIFromMemPointer(codeUnit, vm, ptrMethods);
                                if(jni != null) {
                                    registered.add(jni);
                                }
                            }
                        }
                    }
                }
            }
        }
        return registered;
    }

    @SuppressWarnings("unchecked")
    private boolean isBlockCallsRegisterNatives(INativeCodeUnit<?> codeUnit, BasicBlock<?> block) {
        List<IInstruction> instructions = (List<IInstruction>)block.getInstructions();
        long address = block.getAddressOfInstruction(instructions.size() - 1);
        IInstruction insn = instructions.get(instructions.size() - 1);
        if(insn.getMnemonic().startsWith("BL")) {
            IFlowInformation flow = insn.getRoutineCall(address);
            if(flow.isBrokenKnown() && flow.getTargets().size() == 1) {
                long targetAddress = flow.getTargets().get(0).getAddress();
                String label = codeUnit.getAddressLabel(Formatter.toHexString(targetAddress, false) + "h");
                // expect a method named *RegisterNatives*
                if(label != null && label.contains("RegisterNatives")) {
                    logger.i("Found potential RegisterNatives call @%xh", address);
                    return true;
                }
            }
        }
        return false;
    }

    private static boolean hasVariable(IEGeneric ire) {
        IdRanges use = new IdRanges();
        ire.getUsed(use);
        return !use.getVarIds().isEmpty();
    }

}
