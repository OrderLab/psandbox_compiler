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
#include <llvm/Transforms/Utils/BasicBlockUtils.h>

#include "llvm/Demangle/Demangle.h"
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
#include "llvm/Transforms/Utils/Cloning.h"

using namespace llvm;
#define DEPTH 2

bool pSandboxAnalysisPass::runOnModule(Module &M) {
  GenericCallGraph CG;
  buildCallgraph(M,&CG);
  buildWrapper(M, &CG);

  for (auto maps: startFunctionWrapperMap) {
    FuncNode *node = CG.createNode(maps.first);
    if (node) {
      errs() << "the Function is " << node->getValue()->getName() << "\n";
    }
    for (auto wrapper: maps.second) {
      errs() << "the wrapper is " << wrapper->getName() << "\n";
    }
  }

  for (auto maps: endFunctionWrapperMap) {
    FuncNode *node = CG.createNode(maps.first);
    if (node) {
      errs() << "End Function is " << node->getValue()->getName().data() << "\n";
    }
    for (auto wrapper: maps.second) {
      errs() << "End wrapper is " << wrapper->getName() << "\n";
    }
  }

  buildInstrumentationMap(M,&CG,DEPTH);
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
    Function *start_f,*end_f;
    start_f = getFunctionWithName(targetFun.start_fun.name, M);
    end_f = getFunctionWithName(targetFun.end_fun.name, M);
    if(!start_f)
      continue;

    // handle the end function first
    if(start_f != end_f) {
      resourceUseMap[end_f];
      endFunctionWrapperMap[end_f];
      FuncNode *node = CG->createNode(end_f);
      auto Callers = node->getCallers();
      endFunctionWrapperMap[end_f].emplace_back(end_f);
      for (auto caller: Callers) {
        if (isWrapper(caller, targetFun.start_fun)) {
          endFunctionWrapperMap[end_f].emplace_back(caller.second->getValue());
        }
      }
    }

    resourceUseMap[start_f];
    startFunctionWrapperMap[start_f];
    FuncNode *node = CG->createNode(start_f);
    auto Callers = node->getCallers();
    startFunctionWrapperMap[start_f].emplace_back(start_f);
    for (auto caller: Callers) {
        if (isWrapper(caller,targetFun.start_fun)) {
          int flag = 1;

          if(start_f != end_f) {
            for (BasicBlock &BB : *caller.second->getValue())
              for (Instruction &I : BB) {
                if (auto *CS = dyn_cast<CallBase>(&I)) {
                  Function *Callee = CS->getCalledFunction();
                  if (!Callee || !Intrinsic::isLeaf(Callee->getIntrinsicID())) {
                    if (CallInst *call = dyn_cast<CallInst>(&I)) {
                      //this adds the void bitcasted functions
                      Callee = llvm::dyn_cast<llvm::Function>(call->getCalledValue()->stripPointerCasts());
                      if(Callee) {
                        auto end_wrappers = endFunctionWrapperMap[end_f];
                        for (auto wrapper :end_wrappers) {
                          if(Callee->getName() == wrapper->getName())
                            flag = 0;
                        }
                      }


                    }
                  }
                  else  if (!Callee->isIntrinsic()) {
                    auto end_wrappers = endFunctionWrapperMap[end_f];
                    for (auto wrapper :end_wrappers) {
                      if(wrapper)
                      if(Callee->getName() == wrapper->getName())
                        flag = 0;
                      filterWrapperMap[start_f].emplace_back(caller.second->getValue());
                    }
                  }
                }
              }
          }

        if(flag)
          startFunctionWrapperMap[start_f].emplace_back(caller.second->getValue());
      }
    }
  }
}

void pSandboxAnalysisPass::buildCallgraph(Module &M, GenericCallGraph *CG) {
  for (Function &F : M) {
      addToCallGraph(&F,CG);
  }
}

void pSandboxAnalysisPass::buildInstrumentationMap(Module &M, GenericCallGraph *CG, int depth) {
  std::map<Function*, std::vector<Function*>> map = startFunctionWrapperMap;
 //TODO: check the caller of the caller
    for (auto wrappers: map) {
      for (auto wrapper: wrappers.second) {
        std::vector<Function*> nodes;
        nodes.push_back(wrapper);
        for (int i = 0; i < depth; i++) {
          std::vector<Function*> temp;
          for(auto w: nodes) {
            FuncNode *node = CG->createNode(w);
            auto Callers = node->getCallers();
            for (auto caller: Callers) {
              std::set<usageRecord> &usages = resourceUseMap[wrappers.first];

              if (isCritical(caller)) {
                int flag = 1;
                Function *start_f,*end_f;
                start_f = wrappers.first;

                for (auto target_fun : targetFunctions) {
                  if(target_fun.start_fun.name == start_f->getName()) {
                    end_f = getFunctionWithName(target_fun.end_fun.name, M);
                    break;
                  }
                }
//                if(caller.second->getValue()->getName() == "VXID_Get")
//                  errs() << "start " <<start_f->getName() <<"; end " << end_f->getName() << "\n";
                if(start_f != end_f) {
                  for (BasicBlock &BB : *caller.second->getValue())
                    for (Instruction &I : BB) {
                      if (auto CS = CallSite(&I)) {
                        Function *Callee = CS.getCalledFunction();

                        if (!Callee || !Intrinsic::isLeaf(Callee->getIntrinsicID())) {
                          if (CallInst *call = dyn_cast<CallInst>(&I)) {
                            //this adds the void bitcasted functions

                            Callee = llvm::dyn_cast<llvm::Function>(call->getCalledValue()->stripPointerCasts());
                            if(Callee) {
                              auto end_wrappers = endFunctionWrapperMap[end_f];
                              for (auto end_wrapper :end_wrappers) {

                                if(Callee->getName() == end_wrapper->getName()) {
                                  flag = 0;
                                  break;
                                }
                              }
                            }
                          }
                        } else  if (!Callee->isIntrinsic()) {
                          auto end_wrappers = endFunctionWrapperMap[end_f];
                          for (auto end_wrapper :end_wrappers) {
                            if(Callee->getName() == end_wrapper->getName()) {
                              flag = 0;
                              break;
                            }
                          }
                        }
                      }
                    }
                }

                if(flag) {
                  std::pair<Instruction *, Function *> record;
                  record.first = dyn_cast<Instruction>(caller.first);
                  record.second = caller.second->getValue();
                  usages.insert(record);
                }
              } else {
                std::vector<Function *> filerFunctions =  filterWrapperMap[wrappers.first];
                int is_filter = 0;
                for(auto filerFunction : filerFunctions ) {
                    if (filerFunction == caller.second->getValue())
                      is_filter = 1;
                }
                if(!is_filter)
                  temp.push_back(caller.second->getValue());
              }
            }
          }
          nodes.clear();
          nodes = temp;
        }

    }
  }
}

void pSandboxAnalysisPass::addToCallGraph(Function *F, GenericCallGraph *CG) {
  FuncNode *node = CG->createNode(F);

  // Look for calls by this function.
  for (BasicBlock &BB : *F)
    for (Instruction &I : BB) {
      if (auto *CS = dyn_cast<CallBase>(&I)) {
        Function *Callee = CS->getCalledFunction();
        if (!Callee || !Intrinsic::isLeaf(Callee->getIntrinsicID())) {
          if (CallInst *call = dyn_cast<CallInst>(&I)) {
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
//  if(bi->getFunction()->getName() == "VXID_Get")
//    errs() << "condi " << *val << "\n";
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
      if (!exitBlocks.size())
        return false;
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

//    errs() << "with loop " << f->getName() << "; exit block  " << loop->getNumBackEdges() <<  "\n";
    for (BasicBlock::iterator inst = loop->getExitingBlock()->begin(); inst != loop->getExitingBlock()->end(); inst++) {
      auto *bi = dyn_cast<BranchInst>(inst);
      if(!bi)
        continue;

//      errs() << "fun " << f->getName() << "\nbi " << *bi << "\n";
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
//    if(inst->getFunction()->getName() == "VXID_Get")
//      errs() << "value " << *v << "\n";
    if(isa<Constant>(v))
      continue;

    if(isa<Instruction>(v)) {
      auto i =  dyn_cast<Instruction>(v);

      if (auto *storeInst = dyn_cast<StoreInst>(i)) {
        bool is_pont = storeInst->getValueOperand()->getType()->isPointerTy();
        if (!is_pont && loop && !loop->contains(i))
          continue;
        if (isa<GlobalValue>(storeInst->getValueOperand())) {
          return true;
        }  else {
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
    } else {
      // TODO: check one level
//     return true;
      if (isa<Argument>(v))
        return true;
//    }
    }

    for (User *U : v->users()) {
//      if(inst->getFunction()->getName() == "VXID_Get")
//        errs() << "use " << *U << "\n";
      if(isa<Instruction>(U)) {
        auto i =  dyn_cast<Instruction>(U);
        if (auto *storeInst = dyn_cast<StoreInst>(i)) {
            bool is_pont = storeInst->getValueOperand()->getType()->isPointerTy();

            if (!is_pont && loop && !loop->contains(i))
              continue;

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

        if (!loop || loop->contains(i)) {
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
  Function* f, *new_f;
  std::vector<BasicBlock *> succBlocks, visitedBlocks;
  ValueToValueMapTy VMap;
  if(!bi)
    return false;

  f = bi->getFunction();

  new_f = CloneFunction(f, VMap);
  if (funcInfo.isargument && !compareValue(bi, funcInfo))
      return false;

  PostDominatorTree DT = PostDominatorTree();
  DT.recalculate(*new_f);

  return DT.dominates(bi->getParent(),f->getEntryBlock().getFirstNonPHI()->getParent());
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