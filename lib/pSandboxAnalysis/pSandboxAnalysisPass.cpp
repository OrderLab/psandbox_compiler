//
// Created by yigonghu on 12/9/21.
//

#include <fstream>
#include <iostream>
#include <set>
#include <string>
#include <unordered_map>
#include <vector>
#include <pSandboxAnalysisPass.h>
#include <llvm/Analysis/LoopInfo.h>

#include "llvm/Demangle/Demangle.h"
#include "llvm/ADT/MapVector.h"
#include "llvm/Analysis/TargetLibraryInfo.h"
#include "llvm/IR/CallSite.h"
#include "llvm/IR/InstrTypes.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Operator.h"
#include "llvm/IR/Value.h"
#include "llvm/Pass.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Analysis/PostDominators.h"

using namespace llvm;

bool pSandboxAnalysisPass::runOnModule(Module &M) {
//  Function *startFun = getFunctionWithName(syscall_functions[0].start_fun, M);
errs() << "the start is " << syscall_functions[0].start_fun <<"\n";

  for (Module::iterator function = M.begin(), moduleEnd = M.end(); function != moduleEnd; function++) {
    for (Function::iterator block = function->begin(), functionEnd = function->end();block != functionEnd; ++block) {
      for (BasicBlock::iterator instruction = block->begin(), blockEnd = block->end();
      instruction != blockEnd; instruction++) {
        Instruction *inst = dyn_cast<Instruction>(instruction);
        CallInst *callInst;
        Function *calledFunction;

        if (!isa<CallInst>(instruction))
          continue;

        callInst = dyn_cast<CallInst>(instruction);
        calledFunction = callInst->getCalledFunction();
        if (!calledFunction)
          continue;

        if (calledFunction->getName() == syscall_functions[0].start_fun) {
          errs() << "the caller is " << function->getName() << "\n";
        }
      }
    }
  }
//  CallGraph &CG = getAnalysis<CallGraphWrapperPass>().getCallGraph();

//  callerGraph[startFun];
//  for (CallGraph::iterator node = CG.begin(); node != CG.end(); node++) {
//    Function* nodeFunction = const_cast<Function *> (node->first);
//    if (!nodeFunction) {
//      continue;
//    }
//
//    for (CallGraphNode::iterator callee_it = node->second->begin(); callee_it != node->second->end(); callee_it++) {
//      if (!callee_it->second->getFunction())
//        continue;
//
//      // create caller graph
//      if (demangleName(startFun->getName()) == demangleName(callee_it->second->getFunction()->getName())) {
//        std::vector<CallerRecord> &callers = callerGraph[startFun];
//        std::pair<Instruction *, Function *> record;
//
//        record.first = dyn_cast<Instruction>(callee_it->first);
//        record.second = nodeFunction;
//        callers.emplace_back(record);
//      }
//    }
//  }

//    for (auto callers : callerGraph) {
//      for(auto record: callers.second) {
//
//        int flag = 0;
//        Function* f = record.first->getParent()->getParent();
//        for (Function::iterator BI = f->begin(), BE = f->end(); BI != BE; ++BI) {
//          for (BasicBlock::iterator I = BI->begin(), E = BI->end(); I != E; I++) {
//            CallInst *callInst;
//            Function *calledFunction;
//            if (!isa<CallInst>(I))
//              continue;
//
//            callInst = dyn_cast<CallInst>(I);
//            calledFunction = callInst->getCalledFunction();
//            if (!calledFunction)
//              continue;
//            if (demangleName(calledFunction->getName()) == functions[0].end_fun) {
//              flag = 1;
//              if (checkUsage(record.first,callInst)) {
//                psandboxGraph[startFun].emplace_back(record);
//                goto loop_end;
//              }
//            }
//          }
//        }
//        loop_end:
//        if(!flag) {
//          psandboxGraph[startFun].emplace_back(record);
//        }
//      }
//    }
//
//    errs() << "size: " << psandboxGraph.size() << "\n";
//    for (auto callers : psandboxGraph) {
//      errs() << "the key function: "<< callers.first->getName() << "\n";
//      errs() << "size " << callers.second.size() << "\n";
////      for(auto record: callers.second) {
////        errs() << "the Inst: " << *record.first << "; function " << record.second->getName()<< "\n";
////      }
//      errs() << "---------------------\n";
//    }
//
//    errs() << "callerGraph size: " << callerGraph.size() << "\n";
//    for (auto callers : callerGraph) {
//      errs() << "callerGraph the key function: "<< callers.first->getName() << "\n";
//      errs() << "callerGraph size " << callers.second.size() << "\n";
//      //      for(auto record: callers.second) {
//      //        errs() << "the Inst: " << *record.first << "; function " << record.second->getName()<< "\n";
//      //      }
//      errs() << "---------------------\n";
//    }
    return true;
}

bool pSandboxAnalysisPass::instrIsInaLoop(LoopInfo &loopInfo, Instruction *instr) {
  for (auto loop : loopInfo) if (instrIsInLoop(loop, instr)) return true;

  return false;
}

bool pSandboxAnalysisPass::instrIsInLoop(Loop *loop, Instruction *instr) {
  if (loop->contains(instr))
    return true;

//  else {
//    for (auto subLoop : loop->getSubLoops()) {
//      if (instrIsInLoop(loop, instr)) return true;
//    }
//
//    return false;
//  }

}

bool pSandboxAnalysisPass::checkUsage(Instruction* bi, Instruction* ei) {
  Function* f = bi->getFunction();
  int flag = 0;
  DominatorTree DT = DominatorTree();
  DT.recalculate(*bi->getFunction());
  LoopInfo *LI = new LoopInfo();
  LI->releaseMemory();
  LI->analyze(DT);
  for (Function::iterator BI = f->begin(), BE = f->end(); BI != BE; ++BI) {
    for (BasicBlock::iterator I = BI->begin(), E = BI->end(); I != E; I++) {
      Instruction *inst = dyn_cast<Instruction>(I);
      if(inst == bi)  {
        flag = 1;
        continue;
      } else if (inst == ei) {
        flag = 0;
        continue;
      }
      if (!flag)
        continue;

      if (isa<CallInst>(I) || isa<InvokeInst>(I))
        return true;

      if(instrIsInaLoop(*LI,inst)) {
        return true;
      }

    }
  }
  return false;
}

  // Helper function to demangle a function name given a mangled name
  // Note: This strips out the function arguments along with the function number
std::string pSandboxAnalysisPass::demangleName(std::string mangledName) {
  if (mangledName.size() == 0) return "";

  const char *mangled = mangledName.c_str();
  char *buffer = (char *)malloc(strlen(mangled));
  size_t length = strlen(mangled);
  int *status = nullptr;
  char *demangled = itaniumDemangle(mangled, buffer, &length, status);

  if (demangled != NULL) {
    std::string str(demangled);
    // Strip out the function arguments
    size_t pos = str.find_first_of("(");
    free(demangled);
    return str.substr(0, pos);
  }

  return mangledName;
}

  // Helper function to find a function given the name. Internally demangles the
  // name
Function *pSandboxAnalysisPass::getFunctionWithName(std::string name, Module &M) {
  for (Module::iterator I = M.begin(), E = M.end(); I != E; ++I) {
    Function &F = *I;
    std::string demangled = demangleName(F.getName());
    if (demangled.rfind(name, 0) == 0)  {
      errs() << demangled << "\n";
      return &F;
    }
  }
  return NULL;
}

void pSandboxAnalysisPass::getAnalysisUsage(AnalysisUsage &AU) const {
  AU.addRequired<llvm::CallGraphWrapperPass>();
  AU.addRequired<DominatorTreeWrapperPass>();
}

char pSandboxAnalysisPass::ID = 1;
RegisterPass<pSandboxAnalysisPass> X(
    "psandbox", "Analysis to find the instrumentation point for psandbox");