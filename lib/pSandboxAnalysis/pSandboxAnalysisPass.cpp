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
  buildWrapper(M, &CG);

  for (auto maps: functionWrapperMap) {
    FuncNode *node = CG.createNode(maps.first);
    if (node) {
      errs() << "the Function is " << node->getValue()->getName() << "\n";
    }
    for (auto wrapper: maps.second) {
      errs() << "the wrapper is " << wrapper->getName() << "\n";
    }
  }

  buildInstrumentationMap(&CG,DEPTH);
  errs() << "resourceUseMap size: " << resourceUseMap.size() << "\n";
    for (auto callers : resourceUseMap) {
      errs() << "resourceUseMap the key function: "<< callers.first->getName() << "\n";
      errs() << "resourceUseMap size " << callers.second.size() << "\n";
      for(auto record: callers.second) {
          errs() << " function " << record.second->getName()<< "; point 4" << "\n";
      }
      errs() << "---------------------\n";
    }
    return true;
}

void pSandboxAnalysisPass::buildWrapper(Module &M, GenericCallGraph *CG) {
  for (auto targetFun :targetFunctions) {

    Function *f = getFunctionWithName(targetFun.start_fun.name, M);
    if(!f)
      continue;
    resourceUseMap[f];
    functionWrapperMap[f];
    FuncNode *node = CG->createNode(f);
    auto Callers = node->getCallers();
    functionWrapperMap[f].emplace_back(f);
    for (auto caller: Callers) {
//      errs() << "caller " << caller.second->getValue()->getName() << "\n";
//      std::vector<usageRecord> &usages = resourceUseMap[f];
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
 //TODO: check the caller of the caller
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
          }
        }
    }
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



bool pSandboxAnalysisPass::isConditionGlobal(BranchInst* bi, Loop *loop) {
  Value *val;

  if (bi->isConditional())
    val = bi->getCondition();
  else
   return false;
//  errs() << "condi " << *val << "\n";
  if (auto *inst = dyn_cast<Instruction>(val)) {
    if (isa<CmpInst>(val)) {
      CmpInst *ci = dyn_cast<CmpInst>(inst);
      Value *LHS = ci->getOperand(0);
      Value *RHS = ci->getOperand(1);
      if (isa<Instruction>(LHS)) {
        auto i = dyn_cast<Instruction>(LHS);
        if (isa<CallInst>(i)) {
          auto callInst = dyn_cast<CallInst>(i);
          Function* fun = callInst->getCalledFunction();
          if(fun) {
            for (BasicBlock &BB: *fun) {
              for (Instruction &I: BB) {
                if (isa<ReturnInst>(I)) {
                  auto retI = dyn_cast<ReturnInst>(&I);
                  if (isShared(dyn_cast<Instruction>(retI->getReturnValue()), NULL))
                    return true;
                }
              }
            }
          }
        } else if (isShared(i,loop)) {
          return true;
        }
      }

      if (isa<Instruction>(RHS)) {
        auto i = dyn_cast<Instruction>(RHS);
        if (isa<CallInst>(i)) {
          auto callInst = dyn_cast<CallInst>(i);
          Function* fun = callInst->getCalledFunction();
          if(fun) {
            for (BasicBlock &BB: *fun) {
              for (Instruction &I: BB) {
                if (isa<ReturnInst>(I)) {
                  auto retI = dyn_cast<ReturnInst>(&I);
                  if (isShared(dyn_cast<Instruction>(retI->getReturnValue()), NULL))
                    return true;
                }
              }
            }
          }
        } else if (isShared(i,loop))
          return true;
      }
    } else if (isa<TruncInst>(val)) {
      auto truncInst = dyn_cast<TruncInst>(inst);
      if (isShared(dyn_cast<Instruction>(truncInst->getOperand(0)),loop))
        return true;
    } else if (isa<CallInst>(val)) {
      auto callInst = dyn_cast<CallInst>(inst);
      Function* fun = callInst->getCalledFunction();
      if(fun) {
        for (BasicBlock &BB : *fun) {
          for (Instruction &I : BB) {
            if (isa<ReturnInst>(I)) {
              auto retI = dyn_cast<ReturnInst>(&I);
//              errs() << "ret ins " << *retI->getReturnValue() << "\n";
              if (isShared(dyn_cast<Instruction>(retI->getReturnValue()), NULL))
                return true;
            }
          }
        }
      }
      return false;
    }
  }
  return false;
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
    if(!loop->getExitingBlock()) {
      SmallVector<BasicBlock *, 16> exitBlocks;
      bool is_shared=true;
      loop->getExitingBlocks(exitBlocks);
//      errs() << "no loop " << f->getName() << "; exit block " << exitBlocks.size() <<"\n";
      for(auto EB: exitBlocks) {
//        errs() << "fun " << f->getName() << "\nbi " << *EB << "\n";
        for (BasicBlock::iterator inst = EB->begin(); inst != EB->end(); inst++) {
          auto *bi = dyn_cast<BranchInst>(inst);
          if(!bi)
            continue;
          is_shared = is_shared && isConditionGlobal(bi,loop);
        }
      }
      if (is_shared)
        return true;
      else
        return false;
    }

    errs() << "with loop " << f->getName() << "; exit block  " << loop->getNumBackEdges() <<  "\n";
    for (BasicBlock::iterator inst = loop->getExitingBlock()->begin(); inst != loop->getExitingBlock()->end(); inst++) {
      auto *bi = dyn_cast<BranchInst>(inst);
      if(!bi)
        continue;
      if(f->getName() == "RequestCheckpoint")
          errs() << "fun " << f->getName() << "\nbi " << *bi << "\n";
      return isConditionGlobal(bi,loop);
    }
  }
  return false;
}

bool pSandboxAnalysisPass::isShared(Instruction* inst, Loop *loop) {
  std::vector<Value *> variables, visitedVariable;
  variables.push_back(inst);

  while (!variables.empty()) {
    Value *v = variables.back();
    visitedVariable.push_back(v);
    variables.pop_back();

    if(isa<Constant>(v))
      continue;
//    errs() << "val " << *v << "\n";
    if(isa<Instruction>(v)) {
      auto i =  dyn_cast<Instruction>(v);
      if (!loop || loop->contains(i)) {
        if (auto *storeInst = dyn_cast<StoreInst>(i)) {
          if (isa<GlobalValue>(storeInst->getValueOperand())) {
            return true;
          } else {
            if (std::find(visitedVariable.begin(), visitedVariable.end(), storeInst->getValueOperand())== visitedVariable.end())
              variables.push_back(storeInst->getValueOperand());

          }
        }

        if (auto *loadInst = dyn_cast<LoadInst>(i)) {
         if (isa<GlobalValue>(loadInst->getPointerOperand())) {
           return true;
          } else {
           if(std::find(visitedVariable.begin(), visitedVariable.end(), loadInst->getPointerOperand())== visitedVariable.end()) {
             variables.push_back(loadInst->getPointerOperand());
           }
          }
        }

        if (isa<GetElementPtrInst>(i)) {
          auto *getElementPtrInst = dyn_cast<GetElementPtrInst>(i);
          if (!isa<GlobalValue>(getElementPtrInst->getPointerOperand())) {
            if(std::find(visitedVariable.begin(), visitedVariable.end(), getElementPtrInst->getPointerOperand())== visitedVariable.end()) {
              variables.push_back(getElementPtrInst->getPointerOperand());
            }
          } else {
            return true;
          }
        }

        if(isa<ZExtInst>(i)) {
          auto *zexI = dyn_cast<ZExtInst>(i);
          if (!isa<GlobalValue>(zexI->getOperand(0))) {
            if(std::find(visitedVariable.begin(), visitedVariable.end(), zexI->getOperand(0))== visitedVariable.end()) {
              variables.push_back(zexI->getOperand(0));
            }
          } else {
            return true;
          }
        }

        if( auto truncInst = dyn_cast<TruncInst>(i)) {
          if (isa<GlobalValue>(truncInst->getOperand(0))) {
            return true;
          } else {
            if(std::find(visitedVariable.begin(), visitedVariable.end(), truncInst->getOperand(0))== visitedVariable.end()) {
              variables.push_back(truncInst->getOperand(0));
            }
          }

        }
      }
    }

    for (User *U : v->users()) {
//      errs() << "use " << *U << "\n";
      if(isa<Instruction>(U)) {
        auto i =  dyn_cast<Instruction>(U);
        if (!loop || loop->contains(i)) {
          if (auto *storeInst = dyn_cast<StoreInst>(i)) {
            if (storeInst->getValueOperand() == v)
              continue;

            if(isa<ConstantInt>(storeInst->getValueOperand())) {
              return true;
            }

            if (isa<GlobalValue>(storeInst->getValueOperand())) {
              return true;
            } else {
              if (std::find(visitedVariable.begin(), visitedVariable.end(), storeInst->getValueOperand())== visitedVariable.end())
                variables.push_back(storeInst->getValueOperand());
            }
          }

          if (auto *loadInst = dyn_cast<LoadInst>(i)) {
            if (loadInst->getPointerOperand() == v)
              continue;

            if (isa<GlobalValue>(loadInst->getPointerOperand())) {
              return true;
            } else {
              if(std::find(visitedVariable.begin(), visitedVariable.end(), loadInst->getPointerOperand())== visitedVariable.end()) {
                variables.push_back(loadInst->getPointerOperand());
              }
            }
          }
        }

        if (auto *ai = dyn_cast<AllocaInst>(i)) {
          if (std::find(visitedVariable.begin(), visitedVariable.end(), i)== visitedVariable.end())
              variables.push_back(ai);
        }
      }
    }
  }
  return false;
}

bool pSandboxAnalysisPass::compareValue(Instruction *inst, FuncInfo funcInfo) {
  auto *callInst = dyn_cast<CallInst>(inst);
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
        variables.push_back(ai);
      }
    }
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
    if (demangled == name)  {
//      errs() << demangled << "\n";
      return &F;
    }
  }
  return NULL;
}

void pSandboxAnalysisPass::getAnalysisUsage(AnalysisUsage &AU) const {
  AU.addRequired<DominatorTreeWrapperPass>();
  AU.addRequired<llvm::LoopInfoWrapperPass>();
}

char pSandboxAnalysisPass::ID = 1;
RegisterPass<pSandboxAnalysisPass> X(
    "psandbox", "Analysis to find the instrumentation point for psandbox");