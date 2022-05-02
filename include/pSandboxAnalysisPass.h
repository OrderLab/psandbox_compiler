//
// Created by yigonghu on 12/9/21.
//

#include <llvm/Analysis/LoopInfo.h>
#include "llvm/Pass.h"
#include "llvm/IR/Constants.h"
#include "llvm/Analysis/CallGraph.h"


using namespace llvm;
#ifndef STATIC_ANALYZER_INCLUDE_PSANDBOXANALYSISPASS_H_
#define STATIC_ANALYZER_INCLUDE_PSANDBOXANALYSISPASS_H_

typedef struct functionInfo {
   std::string start_fun;
   std::string end_fun;
}FunctionInfo;

static FunctionInfo syscall_functions[] = {
    {"semop","semop"}
};
struct pSandboxAnalysisPass : public ModulePass {
  static char ID;
  typedef std::pair<Instruction*, Function*> CallerRecord;
  bool runOnModule(Module &M) override;
  void getAnalysisUsage(AnalysisUsage &Info) const override;
  Function *getFunctionWithName(std::string name, Module &M);
  std::string demangleName(std::string mangledName);
  bool checkUsage(Instruction* bi, Instruction* ei);
  bool instrIsInaLoop(LoopInfo &loopInfo, Instruction *instr);
  bool instrIsInLoop(Loop *loop, Instruction *instr);
 public:
  pSandboxAnalysisPass() : ModulePass(ID) {}
  std::map<Function*, std::vector<CallerRecord>> callerGraph;
  std::map<Function*, std::vector<CallerRecord>> psandboxGraph;
};

#endif //STATIC_ANALYZER_INCLUDE_PSANDBOXANALYSISPASS_H_
