#include "llvm/Analysis/AliasAnalysis.h"
#include "llvm/Analysis/CaptureTracking.h"
#include "llvm/Analysis/MemoryLocation.h"
#include "llvm/Analysis/MemorySSA.h"
#include "llvm/Analysis/ValueTracking.h"
#include "llvm/ADT/StringExtras.h"
#include "llvm/IR/Dominators.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/Module.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Plugins/PassPlugin.h"
#include "llvm/Support/FormatVariadic.h"
#include "llvm/Support/JSON.h"
#include "llvm/Support/SHA256.h"

#include <algorithm>
#include <set>
#include <string>
#include <vector>

using namespace llvm;

namespace {
bool recorderFunction(const Function &F) {
  return F.hasFnAttribute("osrec.runtime") || F.getName().starts_with("osrec_");
}

Function *directTarget(CallBase &Call) {
  return dyn_cast<Function>(Call.getCalledOperand()->stripPointerCasts());
}

std::string origin(Value *Pointer) {
  Value *Object = getUnderlyingObject(Pointer);
  if (isa<AllocaInst>(Object))
    return "stack";
  if (isa<Argument>(Object))
    return "argument";
  if (isa<GlobalVariable>(Object))
    return "global";
  return "unknown";
}

// A suggestion under ordinary compiler-visible memory semantics. The planner
// does not apply omissions or prove whole-kernel ownership / hidden effects.
bool localStoreDetermines(LoadInst &Load, MemorySSA &MSSA,
                         AAResults &AA, DominatorTree &DT,
                         const DataLayout &DL) {
  if (Load.isVolatile() || Load.isAtomic())
    return false;
  auto *Object = dyn_cast<AllocaInst>(getUnderlyingObject(Load.getPointerOperand()));
  if (!Object || PointerMayBeCaptured(Object, true))
    return false;
  auto *Definition = dyn_cast<MemoryDef>(MSSA.getWalker()->getClobberingMemoryAccess(&Load));
  if (!Definition)
    return false;
  auto *Store = dyn_cast_or_null<StoreInst>(Definition->getMemoryInst());
  if (!Store || Store->isVolatile() || Store->isAtomic() || !DT.dominates(Store, &Load))
    return false;
  TypeSize ReadSize = DL.getTypeStoreSize(Load.getType());
  TypeSize WriteSize = DL.getTypeStoreSize(Store->getValueOperand()->getType());
  return !ReadSize.isScalable() && !WriteSize.isScalable() && ReadSize == WriteSize &&
         AA.alias(MemoryLocation::get(&Load), MemoryLocation::get(Store)) == AliasResult::MustAlias;
}

struct Planner : PassInfoMixin<Planner> {
  explicit Planner(std::string Root) : Root(std::move(Root)) {}
  std::string Root;

  PreservedAnalyses run(Module &M, ModuleAnalysisManager &MAM) {
    json::Array Blockers, External, Functions, Sites;
    std::vector<Function *> Closure;
    std::set<Function *> Seen;
    Function *Entry = M.getFunction(Root);
    if (!Entry || Entry->isDeclaration() || recorderFunction(*Entry)) {
      Blockers.push_back("root is missing, has no body, or belongs to the recorder");
    } else {
      Closure.push_back(Entry);
      Seen.insert(Entry);
    }
    // Only compiler-visible direct calls are included. Asynchronous roots must
    // be analyzed separately and explicitly combined by a future kernel adapter.
    for (size_t Index = 0; Index < Closure.size(); ++Index) {
      for (BasicBlock &BB : *Closure[Index]) {
        for (Instruction &I : BB) {
          auto *Call = dyn_cast<CallBase>(&I);
          if (!Call || Call->isInlineAsm())
            continue;
          Function *Target = directTarget(*Call);
          if (Target && !Target->isDeclaration() && !recorderFunction(*Target) &&
              Seen.insert(Target).second)
            Closure.push_back(Target);
        }
      }
    }
    std::sort(Closure.begin(), Closure.end(), [](Function *A, Function *B) {
      return A->getName() < B->getName();
    });
    auto &FAM = MAM.getResult<FunctionAnalysisManagerModuleProxy>(M).getManager();
    int64_t Site = 1, LoadCount = 0, Candidates = 0;
    for (Function *F : Closure) {
      Functions.push_back(F->getName());
      auto &MSSA = FAM.getResult<MemorySSAAnalysis>(*F).getMSSA();
      auto &AA = FAM.getResult<AAManager>(*F);
      auto &DT = FAM.getResult<DominatorTreeAnalysis>(*F);
      bool HiddenEffects = false;
      for (BasicBlock &BB : *F)
        for (Instruction &I : BB)
          if (auto *Call = dyn_cast<CallBase>(&I))
            HiddenEffects |= Call->isInlineAsm() || !directTarget(*Call);
      int64_t Ordinal = 0;
      for (BasicBlock &BB : *F) {
        for (Instruction &I : BB) {
          ++Ordinal;
          json::Object Record{{"site", Site}, {"function", F->getName()},
                              {"instruction", Ordinal}, {"opcode", I.getOpcodeName()}};
          bool Include = false;
          if (auto *Load = dyn_cast<LoadInst>(&I)) {
            Include = true;
            ++LoadCount;
            bool Candidate = !HiddenEffects && localStoreDetermines(*Load, MSSA, AA, DT, M.getDataLayout());
            Candidates += Candidate;
            Record["decision"] = Candidate ? "omit_candidate" : "record_observation";
            Record["reason"] = Candidate ? "dominating complete store to unescaped local memory" :
                "value not proven reconstructible from private local stores";
            Record["origin"] = origin(Load->getPointerOperand());
            Record["volatile"] = Load->isVolatile();
            Record["atomic"] = Load->isAtomic();
            if (Load->isAtomic())
              Blockers.push_back(F->getName().str() + ": atomic load requires an ordering model");
          } else if (auto *Store = dyn_cast<StoreInst>(&I)) {
            Include = true;
            Record["decision"] = "effect_to_classify";
            Record["origin"] = origin(Store->getPointerOperand());
            Record["volatile"] = Store->isVolatile();
            Record["atomic"] = Store->isAtomic();
            if (Store->isAtomic())
              Blockers.push_back(F->getName().str() + ": atomic store requires an ordering model");
          } else if (isa<AtomicRMWInst>(I) || isa<AtomicCmpXchgInst>(I) || isa<FenceInst>(I)) {
            Include = true;
            Record["decision"] = "requires_atomic_ordering_model";
            Blockers.push_back(F->getName().str() + ": atomic ordering requires a replay model");
          } else if (auto *Call = dyn_cast<CallBase>(&I)) {
            Function *Target = directTarget(*Call);
            if (Call->isInlineAsm() || !Target) {
              Include = true;
              Record["decision"] = "requires_adapter";
              Blockers.push_back(F->getName().str() + ": inline assembly or unresolved indirect call");
            } else if (recorderFunction(*Target)) {
              continue;
            } else if (Target->isIntrinsic()) {
              // Memory-free does not mean deterministic (e.g. cycle counters).
              // Retain every intrinsic until an explicit model is supplied.
              if (Target->getIntrinsicID() != Intrinsic::lifetime_start &&
                  Target->getIntrinsicID() != Intrinsic::lifetime_end &&
                  !isa<DbgInfoIntrinsic>(Call)) {
                Include = true;
                Record["decision"] = "requires_intrinsic_model";
                Blockers.push_back(F->getName().str() + ": intrinsic needs replay classification: " +
                                   Target->getName().str());
              }
            } else {
              Include = true;
              Record["callee"] = Target->getName();
              Record["decision"] = Target->isDeclaration() ? "requires_adapter" : "included_code";
              if (Target->isDeclaration()) {
                External.push_back(Target->getName());
                Blockers.push_back(F->getName().str() + ": external call " + Target->getName().str());
              }
            }
          }
          if (Include) {
            Sites.push_back(std::move(Record));
            ++Site;
          }
        }
      }
    }
    std::string IR;
    raw_string_ostream IROut(IR);
    M.print(IROut, nullptr);
    auto Hash = SHA256::hash(ArrayRef<uint8_t>(
        reinterpret_cast<const uint8_t *>(IR.data()), IR.size()));
    json::Object Plan{{"format", "osrec-analysis-v1"}, {"root", Root},
                      {"llvm_version", LLVM_VERSION_STRING}, {"module_ir_sha256", toHex(Hash, true)},
                      {"target", M.getTargetTriple().str()}, {"analysis_only", true},
                      {"instrumentation_applied", false}, {"omissions_applied", false},
                      {"kernel_replay_ready", false},
                      {"assumption", "ordinary compiler-visible C memory semantics; hidden writers require separate modeling"},
                      {"static_load_sites", LoadCount}, {"local_load_omit_candidates", Candidates},
                      {"functions", std::move(Functions)}, {"external_calls", std::move(External)},
                      {"sites", std::move(Sites)}, {"blockers", std::move(Blockers)}};
    errs() << formatv("{0:2}\n", json::Value(std::move(Plan)));
    return PreservedAnalyses::all();
  }
};
} // namespace

extern "C" LLVM_ATTRIBUTE_WEAK PassPluginLibraryInfo llvmGetPassPluginInfo() {
  return {LLVM_PLUGIN_API_VERSION, "OSRecPlanner", LLVM_VERSION_STRING,
          [](PassBuilder &PB) {
            PB.registerPipelineParsingCallback(
                [](StringRef Name, ModulePassManager &MPM,
                   ArrayRef<PassBuilder::PipelineElement>) {
                  if (!Name.consume_front("osrec-plan<") || !Name.consume_back(">") || Name.empty())
                    return false;
                  MPM.addPass(Planner(Name.str()));
                  return true;
                });
          }};
}
