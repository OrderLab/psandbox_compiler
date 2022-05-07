//
// Created by yigonghu on 12/9/21.
//

#include <llvm/Analysis/LoopInfo.h>
#include "llvm/Pass.h"
#include "llvm/IR/Constants.h"
#include "llvm/Analysis/CallGraph.h"
#include <CallGraph.h>


using namespace llvm;
#ifndef STATIC_ANALYZER_INCLUDE_PSANDBOXANALYSISPASS_H_
#define STATIC_ANALYZER_INCLUDE_PSANDBOXANALYSISPASS_H_

typedef struct functionInfo {
   std::string start_fun;
   std::string end_fun;
}FunctionInfo;

static FunctionInfo targetFunctions[] = {
    {"semop","semop"},
//    {"pthread_mutex_lock","pthread_mutex_unlock"}
};


struct pSandboxAnalysisPass : public ModulePass {
  static char ID;
  typedef std::pair<Instruction*, Function*> usageRecord;
  bool runOnModule(Module &M) override;
  void getAnalysisUsage(AnalysisUsage &Info) const override;
  Function *getFunctionWithName(std::string name, Module &M);
  std::string demangleName(std::string mangledName);
  Loop* getLoop(LoopInfo &loopInfo, Instruction *instr);
  bool isCritical(FuncNode::CallRecord calls);
  bool isWrapper(FuncNode::CallRecord calls);
  Instruction* getVariable(BranchInst* bi);
  Instruction* checkVariableUse(Instruction* inst);
  void buildCallgraph(Module &M, GenericCallGraph *CG);
  void addToCallGraph(Function *F, GenericCallGraph *CG);
  void buildInstrumentationMap(GenericCallGraph *CG);
 public:
  pSandboxAnalysisPass() : ModulePass(ID) {}
  std::map<Function*, std::vector<usageRecord>> resourceUseMap;
  std::map<Function*, std::vector<Function*>> functionWrapperMap;

};

#endif //STATIC_ANALYZER_INCLUDE_PSANDBOXANALYSISPASS_H_
