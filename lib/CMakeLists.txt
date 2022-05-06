


add_library(pSandboxAnalysis MODULE
        ../include/CallGraph.h
        pSandboxAnalysis/pSandboxAnalysisPass.cpp
        ../include/pSandboxAnalysisPass.h
        )

target_link_libraries(pSandboxAnalysis LLVMDemangle)