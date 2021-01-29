#include "llvm/Bitcode/BitcodeWriter.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/SymbolTableListTraits.h"
#include "llvm/IR/Type.h"
#include "llvm/IR/ValueSymbolTable.h"
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
};

namespace Operation
{
  enum Binary
  {
    ADD,
    SUB,
    MUL,
    DIV,
    MOD,
  };
  enum Other
  {
    PHI = MOD + 1,
    CALL,
  };
} // namespace Operation

Value *const generateValue(const json::Value &value, const FunctionState &S)
{
  if (const auto &name = value.getAsString())
  {
    return S.F->getValueSymbolTable()->lookup(*name);
  }
  else if (const auto &number = value.getAsNumber())
  {
    return S.B.getInt32(*number);
  }

  return nullptr;
}

int generateOperation(StringRef op)
{
  if (op == "add")
    return Operation::ADD;
  else if (op == "sub")
    return Operation::SUB;
  else if (op == "mul")
    return Operation::MUL;
  else if (op == "div")
    return Operation::DIV;
  else if (op == "mod")
    return Operation::MOD;
  else if (op == "phi")
    return Operation::PHI;
  else if (op == "call")
    return Operation::CALL;

  return 0;
}

void generateBinaryOperation(const json::Object &instruction, const Operation::Binary operation, const FunctionState &S)
{
  const auto name = instruction.getString("name").getValueOr("");
  const auto lhs = generateValue(*instruction.get("lhs"), S);
  const auto rhs = generateValue(*instruction.get("rhs"), S);

  switch (operation)
  {
  case Operation::ADD:
    S.B.CreateNSWAdd(lhs, rhs, name);
    break;
  case Operation::SUB:
    S.B.CreateNSWSub(lhs, rhs, name);
    break;
  case Operation::MUL:
    S.B.CreateNSWMul(lhs, rhs, name);
    break;
  case Operation::DIV:
    S.B.CreateSDiv(lhs, rhs, name);
    break;
  case Operation::MOD:
    S.B.CreateSRem(lhs, rhs, name);
    break;
  }
}

void generatePHI(const json::Object &instruction, const FunctionState &S)
{
  const auto name = *instruction.getString("name");
  const auto label1 = *instruction.getString("label1");
  const auto name1 = *instruction.getString("name1");
  const auto label2 = *instruction.getString("label2");
  const auto name2 = *instruction.getString("name2");

  const auto T = S.F->getValueSymbolTable();
  const auto V1 = T->lookup(name1);
  const auto BB1 = &*find_if(*S.F, [&label1](auto &BB) { return BB.getName() == label1; });
  const auto V2 = T->lookup(name2);
  const auto BB2 = &*find_if(*S.F, [&label2](auto &BB) { return BB.getName() == label2; });

  const auto phi = S.B.CreatePHI(S.B.getInt32Ty(), 2, name);
  phi->addIncoming(V1, BB1);
  phi->addIncoming(V2, BB2);
}

void generateCall(const json::Object &instruction, const FunctionState &S)
{
  const auto name = instruction.getString("name").getValueOr("");
  const auto callee = *instruction.getString("callee");
  const auto &args = *instruction.getArray("args");

  const auto Callee = S.M.getFunction(callee);

  SmallVector<Value *, 0> Args;
  for (auto &arg : args)
  {
    Args.push_back(generateValue(arg, S));
  }

  S.B.CreateCall(Callee->getFunctionType(), Callee, Args, name);
}

void generateInstruction(const json::Object &instruction, const FunctionState &S)
{
  const auto op = *instruction.getString("op");

  auto operation = generateOperation(op);

  switch (operation)
  {
  case Operation::ADD:
  case Operation::SUB:
  case Operation::MUL:
  case Operation::DIV:
  case Operation::MOD:
    generateBinaryOperation(instruction, Operation::Binary(operation), S);
    break;

  case Operation::PHI:
    generatePHI(instruction, S);
    break;
  case Operation::CALL:
    generateCall(instruction, S);
    break;
  }
}

void generateRet(const json::Object &terminator, const FunctionState &S)
{
  const auto value = generateValue(*terminator.get("value"), S);
  S.B.CreateRet(value);
}

void generateBr(const json::Object &terminator, const FunctionState &S)
{
  const auto Condition = generateValue(*terminator.get("condition"), S);
  const auto True = BasicBlock::Create(S.C, *terminator.getString("true"));
  const auto False = BasicBlock::Create(S.C, *terminator.getString("false"));
  S.B.CreateCondBr(Condition, True, False);
}

void generateTerminator(const json::Object &terminator, const FunctionState &S)
{
  const auto name = *terminator.getString("terminator");

  if (name == "ret")
    generateRet(terminator, S);
  else if (name == "br")
    generateBr(terminator, S);
}

void generateBasicBlock(const json::Object &basicBlock, const FunctionState &S)
{
  const auto label = basicBlock.getString("label").getValueOr("");
  const auto &instructions = *basicBlock.getArray("instructions");
  const auto &terminator = *basicBlock.getObject("terminator");

  auto BB = BasicBlock::Create(S.C, label, S.F);
  S.B.SetInsertPoint(BB);
  auto add = S.B.CreateAdd(S.B.getInt32(5), S.B.getInt32(4));

  for (auto &i : instructions)
  {
    generateInstruction(*i.getAsObject(), S);
  }

  generateTerminator(terminator, S);
}

void generateFunction(const json::Object &function, Module &M)
{
  const auto name = function.getString("name").getValueOr("");
  const auto &args = *function.getArray("args");
  const auto &body = *function.getArray("body");

  IRBuilder<> B(M.getContext());

  const auto IntT = B.getInt32Ty();
  const SmallVector<Type *, 0> ArgsType(args.size(), IntT);
  const auto FType = FunctionType::get(IntT, ArgsType, false);
  const auto F = Function::Create(FType, Function::ExternalLinkage, name, M);

  auto args_i = args.begin();
  for (auto &Arg : F->args())
  {
    Arg.setName(*args_i->getAsString());
    args_i++;
  }

  const FunctionState S{M.getContext(), M, B, F};

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

  for (auto &f : functions)
  {
    generateFunction(*f.getAsObject(), M);
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
