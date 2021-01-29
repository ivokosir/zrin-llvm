#ifdef FALSE
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Support/Host.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Support/TargetRegistry.h"
#include "llvm/Support/TargetSelect.h"
#include "llvm/Target/TargetMachine.h"
#include "llvm/Target/TargetOptions.h"

using namespace llvm;

int buildObjectFromModule(Module &mod)
{
  InitializeAllTargets();
  InitializeAllTargetMCs();
  InitializeAllAsmPrinters();

  auto TargetTriple = sys::getDefaultTargetTriple();
  mod.setTargetTriple(TargetTriple);

  std::string Error;
  auto Target = TargetRegistry::lookupTarget(TargetTriple, Error);

  if (!Target)
  {
    errs() << Error << "\n";
    return 1;
  }

  auto CPU = "generic";
  auto Features = "";
  TargetOptions opt;
  auto RM = Reloc::Model::PIC_;
  auto TargetMachine = Target->createTargetMachine(TargetTriple, CPU, Features, opt, RM);

  mod.setDataLayout(TargetMachine->createDataLayout());

  SmallString<0> destString;
  raw_svector_ostream dest(destString);
  legacy::PassManager pass;
  auto FileType = CGFT_AssemblyFile;

  if (TargetMachine->addPassesToEmitFile(pass, dest, nullptr, FileType))
  {
    errs() << "TargetMachine can't emit a file of this type.\n";
    return 1;
  }

  pass.run(mod);

  outs() << dest.str();

  return 0;
}
#endif
