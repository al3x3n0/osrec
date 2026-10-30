// Conservative facts for EL0 extraction. This is not an execution proof.
#include "llvm/Analysis/AliasAnalysis.h"
#include "llvm/Analysis/CaptureTracking.h"
#include "llvm/Analysis/ConstantFolding.h"
#include "llvm/Analysis/MemorySSA.h"
#include "llvm/Analysis/ValueTracking.h"
#include "llvm/Config/llvm-config.h"
#include "llvm/ADT/StringExtras.h"
#include "llvm/IR/DebugInfoMetadata.h"
#include "llvm/IR/Dominators.h"
#include "llvm/IR/InlineAsm.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/Module.h"
#include "llvm/Passes/PassBuilder.h"
#if LLVM_VERSION_MAJOR >= 22
#include "llvm/Plugins/PassPlugin.h"
#else
#include "llvm/Passes/PassPlugin.h"
#endif
#include "llvm/IR/Verifier.h"
#include "llvm/Support/ErrorHandling.h"
#include "llvm/Transforms/IPO/GlobalDCE.h"
#include "llvm/Transforms/IPO/Internalize.h"
#include "llvm/Support/FormatVariadic.h"
#include "llvm/Support/JSON.h"
#include "llvm/Support/SHA256.h"

#include <set>
#include <algorithm>
#include <map>
#include <vector>

using namespace llvm;

namespace {
bool captured(const Value *V) {
#if LLVM_VERSION_MAJOR >= 20
  return PointerMayBeCaptured(V, true);
#else
  return PointerMayBeCaptured(V, true, true);
#endif
}

std::string moduleTriple(const Module &M) {
#if LLVM_VERSION_MAJOR >= 22
  return M.getTargetTriple().str();
#else
  return M.getTargetTriple();
#endif
}
json::Object site(const Instruction &I, int64_t Ordinal) {
  json::Object S{{"instruction", Ordinal}, {"opcode", I.getOpcodeName()}};
  if (const DebugLoc &D = I.getDebugLoc()) {
    S["file"] = D->getFilename();
    S["line"] = static_cast<int64_t>(D.getLine());
    S["column"] = static_cast<int64_t>(D.getCol());
  }
  return S;
}

bool containsIntegerPointer(const Value *V) {
  auto *C = dyn_cast<ConstantExpr>(V);
  if (!C)
    return false;
  if (C->getOpcode() == Instruction::IntToPtr)
    return true;
  for (const Use &U : C->operands())
    if (containsIntegerPointer(U.get()))
      return true;
  return false;
}

struct Targets {
  std::set<Function *> Functions;
  std::set<Value *> Active;
  unsigned Budget = 128;
  const DataLayout &DL;
  MemorySSA &MSSA;
  AAResults &AA;
  DominatorTree &DT;

  bool resolve(Value *V) {
    if (Budget == 0)
      return false;
    --Budget;
    V = V->stripPointerCastsAndAliases();
    if (!Active.insert(V).second)
      return false;
    bool Complete = false;
    if (auto *F = dyn_cast<Function>(V)) {
      Functions.insert(F);
      Complete = true;
    } else if (auto *S = dyn_cast<SelectInst>(V)) {
      bool A = resolve(S->getTrueValue());
      bool B = resolve(S->getFalseValue());
      Complete = A && B;
    } else if (auto *P = dyn_cast<PHINode>(V)) {
      Complete = P->getNumIncomingValues() != 0;
      for (Value *Incoming : P->incoming_values())
        Complete = resolve(Incoming) && Complete;
    } else if (auto *L = dyn_cast<LoadInst>(V)) {
      if (!L->isAtomic() && !L->isVolatile()) {
        Value *Pointer = L->getPointerOperand();
        Constant *Address = dyn_cast<Constant>(Pointer);
        if (!Address)
          if (auto *I = dyn_cast<Instruction>(Pointer))
            Address = ConstantFoldInstruction(I, DL);
        // Do not infer registered driver callbacks from mutable or replaceable
        // initializers, even if a constant-folding helper could read one.
        auto *Global = Address ? dyn_cast<GlobalVariable>(getUnderlyingObject(Address)) : nullptr;
        if (Global && Global->isConstant() && Global->hasDefinitiveInitializer() &&
            !Global->isExternallyInitialized() && !Global->isThreadLocal() &&
            Global->getAddressSpace() == 0 && Pointer->getType()->getPointerAddressSpace() == 0)
          if (Constant *Loaded = ConstantFoldLoadFromConstPtr(Address, L->getType(), DL))
            Complete = resolve(Loaded);
        if (!Complete) {
          auto *Object = dyn_cast<AllocaInst>(getUnderlyingObject(Pointer));
          if (Object && !captured(Object)) {
            auto *Definition = dyn_cast<MemoryDef>(MSSA.getWalker()->getClobberingMemoryAccess(L));
            auto *Store = Definition ? dyn_cast_or_null<StoreInst>(Definition->getMemoryInst()) : nullptr;
            if (Store && !Store->isVolatile() && !Store->isAtomic() && DT.dominates(Store, L) &&
                Store->getValueOperand()->getType() == L->getType() &&
                AA.alias(MemoryLocation::get(L), MemoryLocation::get(Store)) == AliasResult::MustAlias)
              Complete = resolve(Store->getValueOperand());
          }
        }
      }
    }
    Active.erase(V);
    return Complete;
  }
};

bool ignoredCall(const Instruction &I) {
  auto *Call = dyn_cast<CallBase>(&I);
  auto *Target = Call ? dyn_cast<Function>(Call->getCalledOperand()->stripPointerCastsAndAliases()) : nullptr;
  return Target && Target->isIntrinsic() &&
         (isa<DbgInfoIntrinsic>(Call) || Target->getIntrinsicID() == Intrinsic::lifetime_start ||
          Target->getIntrinsicID() == Intrinsic::lifetime_end);
}

bool portableIntrinsic(const Function &F) {
  if (!F.isIntrinsic())
    return false;
  auto ID = F.getIntrinsicID();
  return ID == Intrinsic::umax || ID == Intrinsic::umin || ID == Intrinsic::smax || ID == Intrinsic::smin;
}

// Narrow publication contract for the first symbolic exporter. General EL0
// eligibility remains separate from the verifier's supported language subset.
std::string proofObstacle(Instruction &I, MemorySSA &MSSA, AAResults &AA, DominatorTree &DT) {
  if (ignoredCall(I))
    return "";
  for (const Use &U : I.operands())
    if (isa<UndefValue>(U.get()) || isa<PoisonValue>(U.get()))
      return "undef or poison input requires a definedness contract";
  if (auto *Binary = dyn_cast<BinaryOperator>(&I)) {
    unsigned Opcode = Binary->getOpcode();
    if (Opcode != Instruction::Add && Opcode != Instruction::Sub && Opcode != Instruction::Mul &&
        Opcode != Instruction::And && Opcode != Instruction::Or && Opcode != Instruction::Xor)
      return "operation is outside the modular integer proof subset";
    if (auto *Overflow = dyn_cast<OverflowingBinaryOperator>(Binary))
      if (Overflow->hasNoSignedWrap() || Overflow->hasNoUnsignedWrap())
        return "overflow precondition is not covered by the current input contract";
  } else if (auto *Load = dyn_cast<LoadInst>(&I)) {
    auto *Object = dyn_cast<AllocaInst>(getUnderlyingObject(Load->getPointerOperand()));
    auto *Definition = dyn_cast<MemoryDef>(MSSA.getWalker()->getClobberingMemoryAccess(Load));
    auto *Store = Definition ? dyn_cast_or_null<StoreInst>(Definition->getMemoryInst()) : nullptr;
    bool Initialized = Object && !captured(Object) && Store && !Store->isAtomic() && !Store->isVolatile() &&
                       DT.dominates(Store, Load) && Store->getValueOperand()->getType() == Load->getType() &&
                       AA.alias(MemoryLocation::get(Load), MemoryLocation::get(Store)) == AliasResult::MustAlias;
    auto *Global = dyn_cast<GlobalVariable>(getUnderlyingObject(Load->getPointerOperand()));
    if (!Initialized && !(Global && Global->isConstant() && Global->hasDefinitiveInitializer()))
      return "load initialization or external memory needs a stronger contract";
  } else if (auto *Allocation = dyn_cast<AllocaInst>(&I)) {
    auto *Count = dyn_cast<ConstantInt>(Allocation->getArraySize());
    if (!Count || !Count->isOne())
      return "dynamic or aggregate allocation is outside the proof subset";
  } else if (!(isa<StoreInst>(I) || isa<CallBase>(I) || isa<ReturnInst>(I) || isa<BranchInst>(I) ||
               isa<SwitchInst>(I) || isa<PHINode>(I) || isa<SelectInst>(I) || isa<ICmpInst>(I) ||
               isa<ZExtInst>(I) || isa<SExtInst>(I) || isa<TruncInst>(I) || isa<BitCastInst>(I)))
    return "instruction is outside the initial proof subset";
  return "";
}

json::Array instructionGraph(Function &F, MemorySSA &MSSA, AAResults &AA) {
  std::map<Instruction *, int64_t> Ordinals;
  int64_t Ordinal = 0;
  for (BasicBlock &BB : F)
    for (Instruction &I : BB)
      Ordinals[&I] = ++Ordinal;
  json::Array Graph;
  for (BasicBlock &BB : F) {
    for (Instruction &I : BB) {
      json::Object Record = site(I, Ordinals[&I]);
      Record["value"] = I.getName();
      Record["block"] = BB.getName();
      std::set<int64_t> Data, Memory;
      json::Array Arguments;
      for (const Use &U : I.operands()) {
        if (auto *Dependency = dyn_cast<Instruction>(U.get()))
          if (Dependency->getFunction() == &F)
            Data.insert(Ordinals[Dependency]);
        if (auto *Argument = dyn_cast<llvm::Argument>(U.get()))
          Arguments.push_back(static_cast<int64_t>(Argument->getArgNo()));
      }
      if (I.mayReadFromMemory()) {
        auto *Access = dyn_cast_or_null<MemoryUseOrDef>(MSSA.getMemoryAccess(&I));
        std::vector<MemoryAccess *> Pending;
        std::set<MemoryAccess *> Visited;
        if (Access)
          Pending.push_back(Access->getDefiningAccess());
        while (!Pending.empty()) {
          MemoryAccess *Previous = Pending.back();
          Pending.pop_back();
          if (!Visited.insert(Previous).second || MSSA.isLiveOnEntryDef(Previous))
            continue;
          if (auto *Phi = dyn_cast<MemoryPhi>(Previous)) {
            for (unsigned Index = 0; Index < Phi->getNumIncomingValues(); ++Index)
              Pending.push_back(Phi->getIncomingValue(Index));
          } else if (auto *Definition = dyn_cast<MemoryDef>(Previous)) {
            Instruction *Writer = Definition->getMemoryInst();
            bool MayWrite = true;
            if (auto *Load = dyn_cast<LoadInst>(&I))
              MayWrite = isModSet(AA.getModRefInfo(Writer, MemoryLocation::get(Load)));
            else if (auto *Store = dyn_cast<StoreInst>(Writer))
              MayWrite = isRefSet(AA.getModRefInfo(&I, MemoryLocation::get(Store)));
            if (MayWrite)
              Memory.insert(Ordinals[Writer]);
            // A partial write does not define every byte. Continue through
            // all predecessors instead of stopping at the nearest clobber.
            Pending.push_back(Definition->getDefiningAccess());
          }
        }
      }
      std::string Seed;
      if (I.isTerminator())
        Seed = "control_flow_and_return";
      else if (isa<CallBase>(I) && !ignoredCall(I))
        Seed = "preserve_call_behavior";
      else if (auto *Store = dyn_cast<StoreInst>(&I)) {
        auto *Object = dyn_cast<AllocaInst>(getUnderlyingObject(Store->getPointerOperand()));
        if (Store->isVolatile() || Store->isAtomic() || !Object || captured(Object))
          Seed = "observable_or_unclassified_write";
      } else if (I.mayHaveSideEffects())
        Seed = "observable_or_unclassified_effect";
      json::Array DataJSON, MemoryJSON;
      for (int64_t Index : Data)
        DataJSON.push_back(Index);
      for (int64_t Index : Memory)
        MemoryJSON.push_back(Index);
      Record["data_dependencies"] = std::move(DataJSON);
      Record["memory_dependencies"] = std::move(MemoryJSON);
      Record["argument_dependencies"] = std::move(Arguments);
      Record["mandatory_reason"] = Seed;
      if (auto *Operator = dyn_cast<OverflowingBinaryOperator>(&I))
        Record["overflow_flags"] = Operator->hasNoSignedWrap() || Operator->hasNoUnsignedWrap();
      Graph.push_back(std::move(Record));
    }
  }
  return Graph;
}

struct El0Facts : PassInfoMixin<El0Facts> {
  explicit El0Facts(std::string SliceRoot = "") : SliceRoot(std::move(SliceRoot)) {}
  std::string SliceRoot;
  PreservedAnalyses run(Module &M, ModuleAnalysisManager &MAM) {
    json::Array Functions;
    auto &FAM = MAM.getResult<FunctionAnalysisManagerModuleProxy>(M).getManager();
    for (Function &F : M) {
      MemorySSA *MSSA = nullptr;
      AAResults *AA = nullptr;
      DominatorTree *DT = nullptr;
      if (!F.isDeclaration()) {
        MSSA = &FAM.getResult<MemorySSAAnalysis>(F).getMSSA();
        AA = &FAM.getResult<AAManager>(F);
        DT = &FAM.getResult<DominatorTreeAnalysis>(F);
      }
      json::Array Calls, Issues, Memory, PointerArguments, Globals, ProofObstacles;
      std::set<GlobalVariable *> SeenGlobals;
      for (Argument &A : F.args())
        if (A.getType()->isPointerTy())
          PointerArguments.push_back(static_cast<int64_t>(A.getArgNo()));
      auto issue = [&](StringRef Kind, StringRef Detail, const Instruction *I = nullptr,
                       int64_t Ordinal = 0) {
        json::Object S = I ? site(*I, Ordinal) : json::Object{};
        S["kind"] = Kind;
        S["detail"] = Detail;
        Issues.push_back(std::move(S));
      };
      if (F.hasFnAttribute("naked") || F.hasFnAttribute("interrupt"))
        issue("architecture_entry", "naked or interrupt function needs an architecture adapter");
      if (F.getCallingConv() != CallingConv::C && F.getCallingConv() != CallingConv::Fast)
        issue("calling_convention", "non-C calling convention needs ABI review");
      if (F.hasPersonalityFn())
        issue("exception_runtime", "exception personality needs a runtime contract");
      auto memory = [&](Instruction &I, Value *Pointer, bool Write, bool Volatile,
                        bool Atomic, int64_t Ordinal) {
        json::Object S = site(I, Ordinal);
        Value *Object = getUnderlyingObject(Pointer);
        std::string Origin = isa<AllocaInst>(Object) ? "stack" :
                             isa<Argument>(Object) ? "argument" :
                             isa<GlobalVariable>(Object) ? "global" : "unknown";
        S["origin"] = Origin;
        S["write"] = Write;
        S["volatile"] = Volatile;
        S["atomic"] = Atomic;
        S["address_space"] = static_cast<int64_t>(Pointer->getType()->getPointerAddressSpace());
        Type *AccessType = nullptr;
        if (auto *L = dyn_cast<LoadInst>(&I))
          AccessType = L->getType();
        else if (auto *Store = dyn_cast<StoreInst>(&I))
          AccessType = Store->getValueOperand()->getType();
        if (AccessType) {
          TypeSize Bytes = M.getDataLayout().getTypeStoreSize(AccessType);
          S["size_scalable"] = Bytes.isScalable();
          S["minimum_bytes"] = static_cast<int64_t>(Bytes.getKnownMinValue());
        } else if (auto *Intrinsic = dyn_cast<MemIntrinsic>(&I)) {
          if (auto *Length = dyn_cast<ConstantInt>(Intrinsic->getLength()))
            S["length_constant"] = toString(Length->getValue(), 10, false);
          else
            S["length_dynamic"] = true;
        }
        if (auto *G = dyn_cast<GlobalVariable>(Object)) {
          S["global"] = G->getName();
          S["thread_local"] = G->isThreadLocal();
          if (G->isThreadLocal())
            issue("thread_local_state", "TLS/per-CPU state needs an explicit adapter", &I, Ordinal);
        }
        Memory.push_back(std::move(S));
        if (Volatile)
          issue("volatile_access", "classify ordinary memory, MMIO or shared external state", &I, Ordinal);
        if (Atomic)
          issue("atomic_ordering", "EL0 may support this instruction; replay ordering is unresolved", &I, Ordinal);
        if (Pointer->getType()->getPointerAddressSpace() != 0)
          issue("address_space", "non-default address space needs translation review", &I, Ordinal);
      };
      int64_t Ordinal = 0;
      for (BasicBlock &BB : F) {
        for (Instruction &I : BB) {
          ++Ordinal;
          std::string ProofIssue = proofObstacle(I, *MSSA, *AA, *DT);
          if (!ProofIssue.empty()) {
            json::Object S = site(I, Ordinal);
            S["detail"] = ProofIssue;
            ProofObstacles.push_back(std::move(S));
          }
          bool IntegerPointer = isa<IntToPtrInst>(I);
          for (const Use &U : I.operands()) {
            IntegerPointer |= containsIntegerPointer(U.get());
            if (U->getType()->isPointerTy()) {
              Value *Object = getUnderlyingObject(U.get()->stripPointerCastsAndAliases());
              if (auto *G = dyn_cast<GlobalVariable>(Object)) {
                if (SeenGlobals.insert(G).second) {
                  Globals.push_back(json::Object{{"global", G->getName()},
                                                  {"constant", G->isConstant()},
                                                  {"declaration", G->isDeclaration()},
                                                  {"thread_local", G->isThreadLocal()},
                                                  {"address_space", static_cast<int64_t>(G->getAddressSpace())}});
                  if (G->isThreadLocal())
                    issue("thread_local_state", "TLS/per-CPU address needs explicit binding", &I, Ordinal);
                  if (G->getAddressSpace() != 0)
                    issue("address_space", "global address space needs translation review", &I, Ordinal);
                }
              }
            }
          }
          if (IntegerPointer)
            issue("integer_address", "integer-derived address needs relocation/address review", &I, Ordinal);
          if (auto *L = dyn_cast<LoadInst>(&I))
            memory(I, L->getPointerOperand(), false, L->isVolatile(), L->isAtomic(), Ordinal);
          else if (auto *S = dyn_cast<StoreInst>(&I))
            memory(I, S->getPointerOperand(), true, S->isVolatile(), S->isAtomic(), Ordinal);
          else if (isa<AtomicRMWInst>(I) || isa<AtomicCmpXchgInst>(I) || isa<FenceInst>(I))
            issue("atomic_ordering", "synchronization needs a replay ordering contract", &I, Ordinal);
          else if (auto *C = dyn_cast<CallBase>(&I)) {
            // These intrinsics describe ordinary memory effects, not hardware
            // access. Record their operands and leave validity/size to the
            // memory contract; volatile and special address spaces still block.
            if (auto *Transfer = dyn_cast<MemTransferInst>(C)) {
              memory(I, Transfer->getDest(), true, Transfer->isVolatile(), false, Ordinal);
              memory(I, Transfer->getSource(), false, Transfer->isVolatile(), false, Ordinal);
              continue;
            }
            if (auto *Set = dyn_cast<MemSetInst>(C)) {
              memory(I, Set->getDest(), true, Set->isVolatile(), false, Ordinal);
              continue;
            }
            auto *Target = dyn_cast<Function>(C->getCalledOperand()->stripPointerCastsAndAliases());
            if (Target && Target->isIntrinsic() &&
                (isa<DbgInfoIntrinsic>(C) || Target->getIntrinsicID() == Intrinsic::lifetime_start ||
                 Target->getIntrinsicID() == Intrinsic::lifetime_end))
              continue;
            json::Object S = site(I, Ordinal);
            if (C->isInlineAsm()) {
              S["kind"] = "inline_assembly";
              S["assembly"] = cast<InlineAsm>(C->getCalledOperand())->getAsmString();
              issue("inline_assembly", "assembly is opaque until instruction semantics are reviewed", &I, Ordinal);
            } else if (!Target) {
              Targets Resolved{{}, {}, 128, M.getDataLayout(), *MSSA, *AA, *DT};
              bool Complete = Resolved.resolve(C->getCalledOperand());
              json::Array Possible;
              std::vector<Function *> Sorted(Resolved.Functions.begin(), Resolved.Functions.end());
              std::sort(Sorted.begin(), Sorted.end(), [](Function *A, Function *B) {
                return A->getName() < B->getName();
              });
              for (Function *Candidate : Sorted)
                Possible.push_back(json::Object{{"callee", Candidate->getName()},
                                                 {"kind", portableIntrinsic(*Candidate) ? "portable_intrinsic" :
                                                          Candidate->isIntrinsic() ? "intrinsic" :
                                                          Candidate->isDeclaration() ? "external" : "direct"}});
              S["kind"] = Complete ? "resolved_indirect" : "indirect";
              S["targets"] = std::move(Possible);
              S["targets_complete"] = Complete;
              if (!Complete)
                issue("indirect_call", "callback target set is incomplete", &I, Ordinal);
            } else {
              S["callee"] = Target->getName();
              S["kind"] = portableIntrinsic(*Target) ? "portable_intrinsic" : Target->isIntrinsic() ? "intrinsic" :
                          Target->isDeclaration() ? "external" : "direct";
            }
            Calls.push_back(std::move(S));
            if (isa<InvokeInst>(C) || isa<CallBrInst>(C))
              issue("exceptional_call", "exception or assembly control transfer needs an adapter", &I, Ordinal);
          } else if (!(isa<BinaryOperator>(I) || isa<UnaryOperator>(I) || isa<CmpInst>(I) ||
                       isa<CastInst>(I) || isa<GetElementPtrInst>(I) || isa<PHINode>(I) ||
                       isa<SelectInst>(I) || isa<AllocaInst>(I) || isa<ReturnInst>(I) ||
                       isa<BranchInst>(I) || isa<SwitchInst>(I) || isa<UnreachableInst>(I) ||
                       isa<ExtractValueInst>(I) || isa<InsertValueInst>(I) ||
                       isa<ExtractElementInst>(I) || isa<InsertElementInst>(I) ||
                       isa<ShuffleVectorInst>(I) || isa<FreezeInst>(I)))
            issue("unclassified_instruction", I.getOpcodeName(), &I, Ordinal);
        }
      }
      std::string ReturnType;
      raw_string_ostream ReturnOut(ReturnType);
      F.getReturnType()->print(ReturnOut);
      json::Array ArgumentTypes;
      for (Argument &A : F.args()) {
        std::string ArgumentType;
        raw_string_ostream ArgumentOut(ArgumentType);
        A.getType()->print(ArgumentOut);
        ArgumentTypes.push_back(ArgumentType);
      }
      json::Object FunctionRecord{{"name", F.getName()}, {"declaration", F.isDeclaration()},
                                      {"calling_convention", static_cast<int64_t>(F.getCallingConv())},
                                      {"return_type", ReturnType}, {"argument_types", std::move(ArgumentTypes)},
                                      {"variadic", F.isVarArg()},
                                      {"verification_obstacles", std::move(ProofObstacles)},
                                      {"pointer_arguments", std::move(PointerArguments)},
                                      {"global_references", std::move(Globals)},
                                      {"calls", std::move(Calls)}, {"memory", std::move(Memory)},
                                      {"issues", std::move(Issues)}};
      if (F.getName() == SliceRoot && !F.isDeclaration())
        FunctionRecord["instruction_graph"] = instructionGraph(F, *MSSA, *AA);
      Functions.push_back(std::move(FunctionRecord));
    }
    std::string IR;
    raw_string_ostream Stream(IR);
    M.print(Stream, nullptr);
    auto Hash = SHA256::hash(ArrayRef<uint8_t>(reinterpret_cast<const uint8_t *>(IR.data()), IR.size()));
    json::Object Report{{"format", "osrec-el0-facts-v2"}, {"llvm_version", LLVM_VERSION_STRING},
                        {"target", moduleTriple(M)}, {"data_layout", M.getDataLayoutStr()},
                        {"module_ir_sha256", toHex(Hash, true)},
                        {"module_assembly", M.getModuleInlineAsm()}, {"functions", std::move(Functions)}};
    errs() << formatv("{0:2}\n", json::Value(std::move(Report)));
    return PreservedAnalyses::all();
  }
};
// Recompute the dependency closure on the exact input IR. JSON instruction
// ordinals supplied by callers are never accepted as a deletion plan.
struct El0Extract : PassInfoMixin<El0Extract> {
  El0Extract(std::string Root, bool Slice) : Root(std::move(Root)), Slice(Slice) {}
  std::string Root;
  bool Slice;
  PreservedAnalyses run(Module &M, ModuleAnalysisManager &MAM) {
    Function *F = M.getFunction(Root);
    if (!F || F->isDeclaration())
      report_fatal_error("extraction root must have a body");
    if (!M.getModuleInlineAsm().empty() || M.getGlobalVariable("llvm.global_ctors") ||
        M.getGlobalVariable("llvm.global_dtors") || M.getGlobalVariable("llvm.used") ||
        M.getGlobalVariable("llvm.compiler.used"))
      report_fatal_error("module initialization, assembly or forced retention needs an explicit contract");
    StringRef Name = Slice ? "osrec_extracted_entry" : "osrec_reference_entry";
    if (M.getNamedValue(Name))
      report_fatal_error("reserved extraction symbol already exists");
    int64_t Before = 0, Removed = 0;
    for (BasicBlock &BB : *F)
      Before += static_cast<int64_t>(BB.size());
    if (Slice) {
      auto &FAM = MAM.getResult<FunctionAnalysisManagerModuleProxy>(M).getManager();
      auto &MSSA = FAM.getResult<MemorySSAAnalysis>(*F).getMSSA();
      auto &AA = FAM.getResult<AAManager>(*F);
      json::Array Graph = instructionGraph(*F, MSSA, AA);
      std::map<int64_t, json::Object *> Nodes;
      std::vector<int64_t> Pending;
      std::set<int64_t> Kept;
      for (json::Value &Value : Graph) {
        auto *Node = Value.getAsObject();
        int64_t Index = *Node->getInteger("instruction");
        Nodes[Index] = Node;
        if (!Node->getString("mandatory_reason")->empty())
          Pending.push_back(Index);
      }
      while (!Pending.empty()) {
        int64_t Index = Pending.back();
        Pending.pop_back();
        if (!Kept.insert(Index).second)
          continue;
        for (StringRef Edge : {"data_dependencies", "memory_dependencies"})
          for (json::Value &Dependency : *Nodes[Index]->getArray(Edge))
            Pending.push_back(*Dependency.getAsInteger());
      }
      std::set<Instruction *> Omitted;
      int64_t Index = 0;
      for (BasicBlock &BB : *F)
        for (Instruction &I : BB)
          if (!Kept.count(++Index))
            Omitted.insert(&I);
      for (Instruction *I : Omitted)
        for (User *User : I->users()) {
          auto *Consumer = dyn_cast<Instruction>(User);
          if (!Consumer || !Omitted.count(Consumer))
            report_fatal_error("omitted instruction still has a retained use");
        }
      Removed = static_cast<int64_t>(Omitted.size());
      // Drop the whole omitted subgraph before deleting any node. This handles
      // cycles without substituting undef/poison into retained instructions.
      for (Instruction *I : Omitted)
        I->dropAllReferences();
      for (Instruction *I : Omitted)
        I->eraseFromParent();
    }
    F->setName(Name);
    F->setLinkage(GlobalValue::ExternalLinkage);
    F->setVisibility(GlobalValue::DefaultVisibility);
    if (verifyModule(M, &errs()))
      report_fatal_error("extracted IR failed verification");
    errs() << formatv("{0:2}\n", json::Value(json::Object{
        {"format", "osrec-el0-extraction-v1"}, {"root", Root}, {"entry", Name},
        {"extraction_applied", Slice}, {"before", Before}, {"removed", Removed},
        {"after", Before - Removed}, {"ir_verified", true}}));
    return PreservedAnalyses::none();
  }
};
} // namespace

extern "C" LLVM_ATTRIBUTE_WEAK PassPluginLibraryInfo llvmGetPassPluginInfo() {
  return {LLVM_PLUGIN_API_VERSION, "OSRecEl0Analyzer", LLVM_VERSION_STRING,
          [](PassBuilder &PB) {
            PB.registerPipelineParsingCallback([](StringRef Name, ModulePassManager &MPM,
                                                   ArrayRef<PassBuilder::PipelineElement>) {
              if (Name == "osrec-el0-facts")
                MPM.addPass(El0Facts());
              else if (Name.consume_front("osrec-el0-facts<") && Name.consume_back(">") && !Name.empty())
                MPM.addPass(El0Facts(Name.str()));
              else
                {
                  StringRef ExtractName = Name;
                  bool Slice = ExtractName.consume_front("osrec-el0-extract<");
                  if (!Slice && !ExtractName.consume_front("osrec-el0-reference<"))
                    return false;
                  if (!ExtractName.consume_back(">") || ExtractName.empty())
                    return false;
                  MPM.addPass(El0Extract(ExtractName.str(), Slice));
                  std::string Entry = Slice ? "osrec_extracted_entry" : "osrec_reference_entry";
                  MPM.addPass(InternalizePass([Entry](const GlobalValue &GV) { return GV.getName() == Entry; }));
                  MPM.addPass(GlobalDCEPass());
                  MPM.addPass(VerifierPass());
                }
              return true;
            });
          }};
}
