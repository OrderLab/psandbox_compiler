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
  std::string name;
  int argument;
  int64_t value;
  int isstruct;
  int index;
} FuncInfo;

typedef struct pairInfo {
  FuncInfo start_fun;
  FuncInfo end_fun;
}PairInfo;

static PairInfo targetFunctions[] = {
//    {{"semop",1,-1,1,1},{"semop",0,0,0,1}},
//    {{"pthread_mutex_lock",0,0,0,0},{"pthread_mutex_unlock",0,0,0,0}},
{{"pg_usleep",0,0,0,0},{"pg_usleep",0,0,0,0}}
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
  bool isWrapper(FuncNode::CallRecord calls,FuncInfo funcInfo);
  bool compareValue(Instruction *i, FuncInfo funcInfo);
  bool isConditionGlobal(BranchInst* bi, Loop *loop);
  bool isShared(Instruction* inst, Loop *loop);
  void buildCallgraph(Module &M, GenericCallGraph *CG);
  void addToCallGraph(Function *F, GenericCallGraph *CG);
  void buildInstrumentationMap(GenericCallGraph *CG, int depth);
  void buildWrapper(Module &M, GenericCallGraph *CG);
 public:
  pSandboxAnalysisPass() : ModulePass(ID) {}
  std::map<Function*, std::vector<usageRecord>> resourceUseMap;
  std::map<Function*, std::vector<Function*>> functionWrapperMap;

};

#endif //STATIC_ANALYZER_INCLUDE_PSANDBOXANALYSISPASS_H_
