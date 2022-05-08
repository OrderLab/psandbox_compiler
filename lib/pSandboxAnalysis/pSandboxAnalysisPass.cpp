//
// Created by yigonghu on 12/9/21.
//


#include <iostream>
#include <set>
#include <string>
#include <unordered_map>
#include <vector>
#include <pSandboxAnalysisPass.h>
#include "CallGraph.h"
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
#define DEPTH 2

bool pSandboxAnalysisPass::runOnModule(Module &M) {
  GenericCallGraph CG;
  buildCallgraph(M,&CG);
  parseTargetFunction(M,&CG);
  for (auto maps: functionWrapperMap) {
    FuncNode *node = CG.createNode(maps.first);
    errs() << "the Function is " << node->getValue()->getName() << "\n";
    for (auto wrapper: maps.second) {
      errs() << "the wrapper is " << wrapper->getName() << "\n";
    }
  }

  buildInstrumentationMap(&CG,DEPTH);



//  do {
//      std::map<Function*, std::vector<Function*>> newWrapper;
//      for (auto node = CG.begin(); node != CG.end(); node++) {
//        Function* func = const_cast<Function *> (node->first);
//
//        if (!func) {
//          continue;
//        }


//        auto Callers = node->second.getCallers();
//
//        for (auto caller = Callers.begin(); caller != Callers.begin(); caller++) {
//          if (!caller->getValue()))
//            continue;

//          if(node->first->getName() == "LWLockAcquire") {
////            for(node->getExternalCallingNode())
//            errs() << " called function " << calledFunction->second->getFunction()->getName() << "\n";
//          }
          // create caller graph
//          for (auto maps: functionWrapperMap) {
//            for (auto wrappers: maps.second) {
//              if (demangleName(wrappers->getName()) == demangleName(calledFunction->second->getFunction()->getName())) {
//                std::vector<usageRecord> &callers = resourceUseMap[maps.first];
//                std::pair<Instruction *, Function *> record;
//                if (isCritical(calledFunction) ) {
//                  record.first = dyn_cast<Instruction>(calledFunction->first);
//                  record.second = func;
//                  callers.emplace_back(record);
//
//                } else if (isWrapper(calledFunction)) {
//                  newWrapper[targetFun].emplace_back(func);
//                  count++;
//                  errs() << "new wrappers: " << func->getName() <<"\n";
//                }
//              }
//            }
//          }
//        }
//      }
//      functionWrapperMap.clear();
//      functionWrapperMap = newWrapper;
//    errs() << "-----------------------------\n";
//    } while (!count);

    errs() << "resourceUseMap size: " << resourceUseMap.size() << "\n";
    for (auto callers : resourceUseMap) {
      errs() << "resourceUseMap the key function: "<< callers.first->getName() << "\n";
      errs() << "resourceUseMap size " << callers.second.size() << "\n";
      for(auto record: callers.second) {
        errs() << " function " << record.second->getName()<< "\n";
      }
      errs() << "---------------------\n";
    }
    return true;
}

void pSandboxAnalysisPass::parseTargetFunction(Module &M,GenericCallGraph *CG) {
  for (auto targetFun :targetFunctions) {
    Function *f = getFunctionWithName(targetFun.start_fun.name, M);

    resourceUseMap[f];
    functionWrapperMap[f];
    FuncNode *node = CG->createNode(f);
    auto Callers = node->getCallers();
    for (auto caller: Callers) {
      std::vector<usageRecord> &usages = resourceUseMap[f];
//      if (isCritical(caller)) {
//        std::pair<Instruction *, Function *> record;
//        record.first = dyn_cast<Instruction>(caller.first);
//        record.second = caller.second->getValue();
//        usages.emplace_back(record);
//      } else
        if (isWrapper(caller,targetFun.start_fun)) {
        functionWrapperMap[f].emplace_back(caller.second->getValue());
      }
    }
  }
}

void pSandboxAnalysisPass::buildCallgraph(Module &M, GenericCallGraph *CG) {
  for (Function &F : M) {
      addToCallGraph(&F,CG);
  }
}


void pSandboxAnalysisPass::buildInstrumentationMap(GenericCallGraph *CG, int depth) {
  std::map<Function*, std::vector<Function*>> wrapper = functionWrapperMap;
  for (int i = 0; i < depth; i++) {
    std::map<Function*, std::vector<Function*>> newWrapper;
    for (auto maps: wrapper) {
      for (auto wrappers: maps.second) {
        FuncNode *node = CG->createNode(wrappers);
        auto Callers = node->getCallers();
        for (auto caller: Callers) {
          std::vector<usageRecord> &usages = resourceUseMap[maps.first];
          if (isCritical(caller)) {
            std::pair<Instruction *, Function *> record;
            record.first = dyn_cast<Instruction>(caller.first);
            record.second = caller.second->getValue();
            usages.emplace_back(record);
          } else if (isWrapper(caller)) {
              functionWrapperMap[maps.first].emplace_back(caller.second->getValue());
              newWrapper[maps.first].emplace_back(caller.second->getValue());
            }
          }
        }
    }
    wrapper.clear();
    wrapper = newWrapper;
  }
}

void pSandboxAnalysisPass::addToCallGraph(Function *F, GenericCallGraph *CG) {
  FuncNode *node = CG->createNode(F);

  // Look for calls by this function.
  for (BasicBlock &BB : *F)
    for (Instruction &I : BB) {
      if (auto CS = CallSite(&I)) {
        Function *Callee = CS.getCalledFunction();
        if (!Callee || !Intrinsic::isLeaf(Callee->getIntrinsicID())) {
          if (CallInst *call = dyn_cast<CallInst>(CS.getInstruction())) {
            //this adds the void bitcasted functions
            Callee = llvm::dyn_cast<llvm::Function>(call->getCalledValue()->stripPointerCasts());
            node->addCall(CS,CG->createNode(Callee));
          }
        }
        else if (!Callee->isIntrinsic()) {
          node->addCall(CS,CG->createNode(Callee));
        }

      }
    }
  }

Instruction* pSandboxAnalysisPass::checkVariableUse(Instruction* inst) {
//  std::vector<Value *> immediate_variable;
//  std::vector<Value *> visited_variable;
//  immediate_variable.push_back(inst);
//  while (!immediate_variable.empty()) {
//    Value *i = immediate_variable.back();
//    visited_variable.push_back(i);
//    immediate_variable.pop_back();
//    for (User *U : i->users()) {
//      if (StoreInst *storeInst = dyn_cast<StoreInst>(U))
//        if (!isa<GlobalValue>(storeInst->getValueOperand())) {
//          if (std::find(visited_variable.begin(),visited_variable.end(),storeInst->getPointerOperand())== visited_variable.end())
//            immediate_variable.push_back(storeInst->getValueOperand());
//        } else {
//          return storeInst;
//        }
//
//      if (LoadInst *loadInst = dyn_cast<LoadInst>(U))
//        if (!isa<GlobalValue>(loadInst->getPointerOperand())) {
//          if(std::find(visited_variable.begin(),visited_variable.end(),loadInst)== visited_variable.end())
//            immediate_variable.push_back(loadInst->getPointerOperand());
//        } else {
//          return loadInst;
//        }
//    }
//  }
//  return NULL;
}

Instruction* pSandboxAnalysisPass::getVariable(BranchInst* bi) {
  Value *val = bi->getCondition();
  for (int i = 0; i < 5; i++) {
    if (Instruction *inst = dyn_cast<Instruction>(val)) {
      errs () << "inst " << *inst<< "\n";
      if (isa<CmpInst>(val)) {
        CmpInst *ci = dyn_cast<CmpInst>(inst);
        Value *LHS = ci->getOperand(0);
        Value *RHS = ci->getOperand(1);
        if (!isa<Constant>(LHS)) {
          val = LHS;
          continue;
        } else if (!isa<Constant>(RHS)) {
          val = RHS;
          continue;
        }
      }

      if (StoreInst *storeInst = dyn_cast<StoreInst>(inst))
        if (!isa<Constant>(storeInst->getValueOperand())) {
          val = storeInst->getPointerOperand();
        }

      if (LoadInst *loadInst = dyn_cast<LoadInst>(inst))
        if (!isa<Constant>(loadInst->getPointerOperand())) {
          val = loadInst->getPointerOperand();
        }

      if (isa<AllocaInst>(inst)) {
//         errs() << "inst " << checkVariableUse(inst) << "\n";
      }
    }

  }
}

bool pSandboxAnalysisPass::isCritical(FuncNode::CallRecord calls) {
  Instruction *i = dyn_cast<Instruction>(calls.first);
  Function* f = i->getFunction();
  DominatorTree DT = DominatorTree();
  DT.recalculate(*f);
  LoopInfo *LI = new LoopInfo();
  LI->releaseMemory();
  LI->analyze(DT);
  if (Loop* loop = getLoop(*LI, i)) {
//    for (BasicBlock::iterator inst = loop->getExitingBlock()->begin(); inst != loop->getExitingBlock()->end(); inst++) {
//      BranchInst *bi = dyn_cast<BranchInst>(inst);
//      if(!bi)
//        continue;
//
//      getVariable(bi);
//      return false;
//    }
    return true;
  }
  return false;
}


bool pSandboxAnalysisPass::compareValue(Instruction *inst, FuncInfo funcInfo) {
  CallInst *callInst = dyn_cast<CallInst>(inst);
  Value *val;
  std::vector<Value *> variables,visitedVariables;
  if(!callInst)
    return false;

  if (!callInst->getCalledFunction()) {
    errs() << "it is a external call\n";
    return false;
  }

  val = callInst->getArgOperand(funcInfo.index);
  variables.push_back(val);
  while (!variables.empty()) {
    Value *i = variables.back();
    visitedVariables.push_back(i);
    variables.pop_back();
    if(!i)
      continue;
    for (User *U : i->users()) {
      int64_t constIntValue;
      if (auto *storeInst = dyn_cast<StoreInst>(U)) {
        auto ci = dyn_cast<ConstantInt>(storeInst->getValueOperand());
        if (ci) {
          constIntValue = ci->getSExtValue();
          if (constIntValue == funcInfo.value)
            return true;
        } else {
          if (std::find(visitedVariables.begin(), visitedVariables.end(), storeInst->getPointerOperand())== visitedVariables.end())
            variables.push_back(storeInst->getValueOperand());
        }
      }

      if (auto *loadInst = dyn_cast<LoadInst>(U)) {
        auto ci = dyn_cast<ConstantInt>(loadInst->getPointerOperand());
        if (ci) {
          constIntValue = ci->getSExtValue();
          if (constIntValue == funcInfo.value)
            return true;
        } else {
          if(std::find(visitedVariables.begin(), visitedVariables.end(), loadInst)== visitedVariables.end())
            variables.push_back(loadInst->getPointerOperand());
        }
      }

      if(funcInfo.isstruct) {
        if (isa<GetElementPtrInst>(U)) {
          auto *getElementPtrInst = dyn_cast<GetElementPtrInst>(U);
          auto *structOffset = dyn_cast<ConstantInt>(getElementPtrInst->getOperand(2));
          if(structOffset->getValue() == funcInfo.index) {
            variables.push_back(U);
          }
        }
      }

      if (auto *ai = dyn_cast<AllocaInst>(U)) {
        errs() << "ai " << *ai << "\n";
        variables.push_back(ai);
      }
    }
>>>>>>> 5b0a11014def23ff1645ad78c8c0b35d1669024a
  }
  return false;
}


bool pSandboxAnalysisPass::isWrapper(FuncNode::CallRecord calls, FuncInfo funcInfo) {
  Instruction *bi = dyn_cast<Instruction>(calls.first);
  Function* f;

  if(!bi)
    return false;

  f = bi->getFunction();
  if (!funcInfo.argument || !compareValue(bi,funcInfo))
      return false;


  DominatorTree DT = DominatorTree();
  DT.recalculate(*f);
  return DT.dominates(f->getEntryBlock().getFirstNonPHI(),bi->getParent());
}

bool pSandboxAnalysisPass::isWrapper(FuncNode::CallRecord calls) {
  Instruction *bi = dyn_cast<Instruction>(calls.first);
  Function* f = bi->getFunction();
  DominatorTree DT = DominatorTree();
  DT.recalculate(*f);
  return DT.dominates(f->getEntryBlock().getFirstNonPHI(),bi->getParent());
}


Loop* pSandboxAnalysisPass::getLoop(LoopInfo &loopInfo, Instruction *instr) {
  for (auto loop : loopInfo)
    if (loop->contains(instr))
      return loop;

  return NULL;
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
//      errs() << demangled << "\n";
      return &F;
    }
  }
  return NULL;
}

void pSandboxAnalysisPass::getAnalysisUsage(AnalysisUsage &AU) const {
  AU.addRequired<llvm::CallGraphWrapperPass>();
  AU.addRequired<DominatorTreeWrapperPass>();
  AU.addRequired<llvm::LoopInfoWrapperPass>();
}

char pSandboxAnalysisPass::ID = 1;
RegisterPass<pSandboxAnalysisPass> X(
    "psandbox", "Analysis to find the instrumentation point for psandbox");