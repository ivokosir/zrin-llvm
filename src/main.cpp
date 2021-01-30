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
  LLVMContext &C;
  Module &M;
  IRBuilder<> &B;
  Function *const F;
  StringMap<Value *> TV;
  StringMap<BasicBlock *> TBB;
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

Value *const generateValue(const json::Value &value, FunctionState &S)
{
  if (const auto name = value.getAsObject())
  {
    return S.TV.lookup(*name->getString("name"));
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
    const auto type = PointerType::getUnqual(S.B.getVoidTy());
    return ConstantPointerNull::get(type);
  }

  return nullptr;
}

BasicBlock *getOrCreateBasicBlock(const StringRef label, FunctionState &S)
{
  auto found = S.TBB.find(label);
  if (found == S.TBB.end())
  {
    auto newBB = BasicBlock::Create(S.C, label, S.F);
    S.TBB[label] = newBB;
    return newBB;
  }
  return found->getValue();
}

Value *generateBinaryOperation(const json::Object &instruction, const llvm::StringRef name, FunctionState &S)
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

Value *generateCall(const json::Object &instruction, const llvm::StringRef name, FunctionState &S)
{
  const auto Caller = S.M.getFunction(*instruction.getObject("caller")->getString("name"));
  const auto Arg = generateValue(*instruction.get("arg"), S);

  return S.B.CreateCall(Caller->getFunctionType(), Caller, {Arg}, name);
}

Value *generatePHI(const json::Object &instruction, const llvm::StringRef name, FunctionState &S)
{
  const auto thenValue = generateValue(*instruction.get("then"), S);
  const auto thenBB = getOrCreateBasicBlock(*instruction.getString("then_label"), S);
  const auto elseValue = generateValue(*instruction.get("else"), S);
  const auto elseBB = getOrCreateBasicBlock(*instruction.getString("else_label"), S);

  const auto phi = S.B.CreatePHI(thenValue->getType(), 2, name);
  phi->addIncoming(thenValue, thenBB);
  phi->addIncoming(elseValue, elseBB);

  return phi;
}

Value *generateInstruction(const json::Object &instruction, FunctionState &S)
{
  const auto tag = *instruction.getString("tag");
  StringRef name = *instruction.getString("name");

  Value *I;
  if (tag == "binary")
    I = generateBinaryOperation(instruction, name, S);
  else if (tag == "call")
    I = generateCall(instruction, name, S);
  else if (tag == "phi")
    I = generatePHI(instruction, name, S);

  S.TV[name] = I;
  return I;
}

void generateRet(const json::Object &terminator, FunctionState &S)
{
  const auto value = generateValue(*terminator.get("value"), S);
  S.B.CreateRet(value);
}

void generateCondBr(const json::Object &terminator, FunctionState &S)
{
  const auto Cond = generateValue(*terminator.get("cond"), S);
  const auto Then = getOrCreateBasicBlock(*terminator.getString("then"), S);
  const auto Else = getOrCreateBasicBlock(*terminator.getString("else"), S);
  S.B.CreateCondBr(Cond, Then, Else);
}

void generateBr(const json::Object &terminator, FunctionState &S)
{
  const auto Label = getOrCreateBasicBlock(*terminator.getString("label"), S);
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
  const auto label = *basicBlock.getString("label");
  const auto &instructions = *basicBlock.getArray("instructions");
  const auto &terminator = *basicBlock.getObject("terminator");

  auto BB = getOrCreateBasicBlock(label, S);
  S.B.SetInsertPoint(BB);
  auto add = S.B.CreateAdd(S.B.getInt32(5), S.B.getInt32(4));

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

  FunctionState S{M.getContext(), M, B, F};

  if (!F->args().empty())
  {
    const auto arg = F->getArg(0);
    arg->setName(param);
    S.TV[param] = arg;
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
