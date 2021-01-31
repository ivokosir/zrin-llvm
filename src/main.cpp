#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/StringMap.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/Bitcode/BitcodeWriter.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Type.h"
#include "llvm/IR/Verifier.h"
#include "llvm/Support/JSON.h"
#include "llvm/Support/MemoryBuffer.h"

using namespace llvm;

struct FunctionState
{
  FunctionState(Module &M, IRBuilder<> &B, Function *const F)
      : C(M.getContext()), M(M), B(B), F(F),
        UnnamedValueTable(), LabelTable() {}
  LLVMContext &C;
  Module &M;
  IRBuilder<> &B;
  Function *const F;
  StringMap<Value *> ValueTable;
  DenseMap<int, Value *> UnnamedValueTable;
  DenseMap<int, BasicBlock *> LabelTable;
};

FunctionType *generateFunctionType(Type *const ret, Type *const param)
{
  if (param->isVoidTy())
  {
    return FunctionType::get(ret, false);
  }
  return FunctionType::get(ret, {param}, false);
}

Type *const generateType(const json::Object &object, const StringRef key, IRBuilder<> &B)
{
  if (const auto fObject = object.getObject(key))
  {
    const auto ret = generateType(*fObject, "ret", B);
    const auto param = generateType(*fObject, "param", B);
    generateFunctionType(ret, param);
  }

  const auto s = *object.getString(key);
  if (s == "void")
    return B.getVoidTy();
  else if (s == "i1")
    return B.getInt1Ty();
  else if (s == "i32")
    return B.getInt32Ty();
  else if (s == "i8*")
    return B.getInt8PtrTy();

  return nullptr;
}

BasicBlock *const generateLabel(const int64_t i, FunctionState &S)
{
  const auto iter = S.LabelTable.find_as(i);
  if (iter == S.LabelTable.end())
  {
    const auto BB = BasicBlock::Create(S.C, "", S.F);
    S.LabelTable[i] = BB;
    return BB;
  }
  return iter->second;
}

Value *const generateValue(const json::Value &value, FunctionState &S)
{
  if (const auto object = value.getAsObject())
  {
    if (const auto name = object->getString("name"))
      return S.ValueTable.lookup(*name);
    else if (const auto iName = object->getInteger("name"))
      return S.UnnamedValueTable.operator[](*iName);
  }
  else if (const auto boolean = value.getAsBoolean())
  {
    return S.B.getInt1(*boolean);
  }
  else if (const auto integer = value.getAsInteger())
  {
    return S.B.getInt32(*integer);
  }
  else if (value.getAsNull())
  {
    return nullptr;
  }

  return nullptr;
}

Value *generateBinary(const json::Object &instruction, const llvm::StringRef name, FunctionState &S)
{
  const auto op = *instruction.getString("op");
  const auto lhs = generateValue(*instruction.get("lhs"), S);
  const auto rhs = generateValue(*instruction.get("rhs"), S);

  if (op == "add")
    return S.B.CreateNSWAdd(lhs, rhs, name);
  else if (op == "sub")
    return S.B.CreateNSWSub(lhs, rhs, name);
  else if (op == "mul")
    return S.B.CreateNSWMul(lhs, rhs, name);
  else if (op == "div")
    return S.B.CreateSDiv(lhs, rhs, name);
  else if (op == "mod")
    return S.B.CreateSRem(lhs, rhs, name);
  else if (op == "and")
    return S.B.CreateAnd(lhs, rhs, name);
  else if (op == "or")
    return S.B.CreateOr(lhs, rhs, name);
  else if (op == "eq")
    return S.B.CreateICmpEQ(lhs, rhs, name);
  else if (op == "ne")
    return S.B.CreateICmpNE(lhs, rhs, name);
  else if (op == "sgt")
    return S.B.CreateICmpSGT(lhs, rhs, name);
  else if (op == "sge")
    return S.B.CreateICmpSGE(lhs, rhs, name);
  else if (op == "slt")
    return S.B.CreateICmpSLT(lhs, rhs, name);
  else if (op == "sle")
    return S.B.CreateICmpSLE(lhs, rhs, name);
  else if (op == "add")
    return S.B.CreateAdd(lhs, rhs, name);
  else if (op == "sub")
    return S.B.CreateSub(lhs, rhs, name);
  else if (op == "mul")
    return S.B.CreateMul(lhs, rhs, name);
  else if (op == "sdiv")
    return S.B.CreateSDiv(lhs, rhs, name);
  else if (op == "srem")
    return S.B.CreateSRem(lhs, rhs, name);

  return nullptr;
}

llvm::CallInst *generateCall(const json::Object &instruction, const llvm::StringRef name, FunctionState &S)
{
  const auto Caller = S.M.getFunction(*instruction.getObject("caller")->getString("name"));
  const auto Arg = generateValue(*instruction.get("arg"), S);

  return S.B.CreateCall(Caller->getFunctionType(), Caller, {Arg}, name);
}

llvm::PHINode *generatePHI(const json::Object &instruction, const llvm::StringRef name, FunctionState &S)
{
  const auto Then = generateValue(*instruction.get("then"), S);
  const auto ThenBB = generateLabel(*instruction.getInteger("then_label"), S);
  const auto Else = generateValue(*instruction.get("else"), S);
  const auto ElseBB = generateLabel(*instruction.getInteger("else_label"), S);

  const auto PHI = S.B.CreatePHI(Then->getType(), 2, name);
  PHI->addIncoming(Then, ThenBB);
  PHI->addIncoming(Else, ElseBB);

  return PHI;
}

Value *generateInstruction(const json::Object &instruction, FunctionState &S)
{
  const auto tag = *instruction.getString("tag");
  const auto name = instruction.getString("name").getValueOr("");

  Value *I;
  if (tag == "binary")
    I = generateBinary(instruction, name, S);
  else if (tag == "call")
    I = generateCall(instruction, name, S);
  else if (tag == "phi")
    I = generatePHI(instruction, name, S);

  if (const auto iName = instruction.getInteger("name"))
    S.UnnamedValueTable[*iName] = I;
  else
    S.ValueTable[name] = I;

  return I;
}

void generateRet(const json::Object &terminator, FunctionState &S)
{
  const auto value = generateValue(*terminator.get("value"), S);
  if (value)
    S.B.CreateRet(value);
  else
    S.B.CreateRetVoid();
}

void generateCondBr(const json::Object &terminator, FunctionState &S)
{
  const auto Cond = generateValue(*terminator.get("cond"), S);
  const auto Then = generateLabel(*terminator.getInteger("then"), S);
  const auto Else = generateLabel(*terminator.getInteger("else"), S);
  S.B.CreateCondBr(Cond, Then, Else);
}

void generateBr(const json::Object &terminator, FunctionState &S)
{
  const auto Label = generateLabel(*terminator.getInteger("label"), S);
  S.B.CreateBr(Label);
}

void generateTerminator(const json::Object &terminator, FunctionState &S)
{
  const auto tag = *terminator.getString("tag");

  if (tag == "ret")
    generateRet(terminator, S);
  else if (tag == "cond_br")
    generateCondBr(terminator, S);
  else if (tag == "br")
    generateBr(terminator, S);
}

void generateBasicBlock(const json::Object &basicBlock, FunctionState &S)
{
  const auto label = *basicBlock.getInteger("label");
  const auto &instructions = *basicBlock.getArray("instructions");
  const auto &terminator = *basicBlock.getObject("terminator");

  const auto BB = generateLabel(label, S);
  S.B.SetInsertPoint(BB);

  for (auto &i : instructions)
  {
    generateInstruction(*i.getAsObject(), S);
  }

  generateTerminator(terminator, S);
}

void generateFunction(const json::Object &function, Module &M, IRBuilder<> &B)
{
  const auto name = *function.getString("name");
  const auto retType = generateType(function, "ret_type", B);
  const auto param = *function.getString("param");
  const auto paramType = generateType(function, "param_type", B);
  const auto &args = *function.getArray("param");
  const auto &body = *function.getArray("blocks");

  const auto FType = generateFunctionType(retType, paramType);
  const auto F = Function::Create(FType, Function::ExternalLinkage, name, M);

  FunctionState S(M, B, F);

  if (!F->args().empty())
  {
    const auto arg = F->getArg(0);
    arg->setName(param);
    S.ValueTable[param] = arg;
  }

  for (auto &bb : body)
  {
    generateBasicBlock(*bb.getAsObject(), S);
  }
}

bool generateModule(const json::Object &module)
{
  const auto moduleName = module.getString("name").getValueOr("");
  const auto &functions = *module.getArray("functions");

  LLVMContext C;
  Module M(moduleName, C);
  IRBuilder<> B(M.getContext());

  for (auto &f : functions)
  {
    generateFunction(*f.getAsObject(), M, B);
  }

  if (verifyModule(M, &errs()))
  {
    return 1;
  }

  M.print(outs(), nullptr);
  //WriteBitcodeToFile(M, outs());

  return 0;
}

int main()
{
  auto errorOrBuffer = MemoryBuffer::getSTDIN();
  if (!errorOrBuffer)
  {
    errs() << "Failed read from stdin: ";
    errs() << errorOrBuffer.getError().message() << "\n";
    return 1;
  }

  auto buffer = errorOrBuffer->get()->getBuffer();
  auto parsedOrError = json::parse(buffer);
  if (auto error = parsedOrError.takeError())
  {
    errs() << error << "\n";
    return 1;
  }

  const auto &rootObject = *parsedOrError->getAsObject();

  return generateModule(rootObject) ? 0 : 1;
}
