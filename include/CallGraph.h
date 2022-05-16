//
// Created by yigonghu on 5/4/22.
//

#ifndef STATIC_ANALYZER_INCLUDE_CALLGRAPH_H_
#define STATIC_ANALYZER_INCLUDE_CALLGRAPH_H_

#include <map>
#include <vector>
namespace llvm {

class FuncNode {
 public:
  typedef std::pair<WeakTrackingVH, FuncNode *> CallRecord;
 private:
  unsigned _id;
  unsigned _scc_id{0};
  std::vector<CallRecord> _calls;
  std::vector<CallRecord> _callers;

  bool _contains(const CallRecord *x, const std::vector<CallRecord> &C) const {
    return std::any_of(C.begin(), C.end(),[x](const CallRecord& s) { return s.second == x->second && s.first == x->first; });
  }

 public:
  Function* value;

  FuncNode(unsigned id, Function* &nd) : _id(id), value(nd){};

  FuncNode(FuncNode &&) = default;

  bool calls(const CallRecord *x) const { return _contains(x, _calls); }
  bool isCalledBy(CallRecord *x) const { return _contains(x, _callers); }

  unsigned getID() const { return _id; }
  unsigned getSCCId() const { return _scc_id; }
  void setSCCId(unsigned id) { _scc_id = id; }

  bool addCall(CallSite CS, FuncNode *x) {
    CallRecord cr ;
    cr.first = CS.getInstruction();
    cr.second = x;
    if (calls(&cr))
      return false;
    _calls.emplace_back(CS.getInstruction(),x);
    cr.first = CS.getInstruction();
    cr.second = this;
    if (!x->isCalledBy(&cr))
      x->_callers.emplace_back(CS.getInstruction(),this);
    return true;
  }

  const std::vector<CallRecord> &getCalls() const { return _calls; }
  // alias for getCalls()
  const std::vector<CallRecord> &successors() const { return getCalls(); }
  const std::vector<CallRecord> &getCallers() const { return _callers; }

  Function* getValue() const { return value; };
};

  class GenericCallGraph {
   public:


   private:
    unsigned last_id{0};

    FuncNode *getOrCreate(Function *v) {
      auto it = _mapping.find(v);
      if (it == _mapping.end()) {
        auto newIt = _mapping.emplace(v, FuncNode(++last_id, v));
        return &newIt.first->second;
      }
      return &it->second;
    }

    std::map<const Function *, FuncNode> _mapping;

   public:
    // just create a node for the value
    // (e.g., the entry node)
    FuncNode *createNode(Function *a) { return getOrCreate(a); }

    // a calls b
    bool addCall(Function *a, Function *b, CallSite i) {
      auto A = getOrCreate(a);
      auto B = getOrCreate(b);
      return A->addCall(i, B);
    }

    const FuncNode *get(const Function *v) const {
      auto it = _mapping.find(v);
      if (it == _mapping.end()) {
        return nullptr;
      }
      return &it->second;
    }

    FuncNode *get(const Function *v) {
      auto it = _mapping.find(v);
      if (it == _mapping.end()) {
        return nullptr;
      }
      return &it->second;
    }

    bool empty() const { return _mapping.empty(); }

    auto begin() -> decltype(_mapping.begin()) { return _mapping.begin(); }
    auto end() -> decltype(_mapping.end()) { return _mapping.end(); }
    auto begin() const -> decltype(_mapping.begin()) {
      return _mapping.begin();
    }
    auto end() const -> decltype(_mapping.end()) { return _mapping.end(); }
  };
}
#endif //STATIC_ANALYZER_INCLUDE_CALLGRAPH_H_
