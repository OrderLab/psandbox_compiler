

add_library(HelloWorld SHARED
        HelloWorld/HelloWorld.cpp
        )

add_library(pSandboxAnalysis SHARED
        pSandboxAnalysis/pSandboxAnalysisPass.cpp
        ../include/pSandboxAnalysisPass.h
        )

target_link_libraries(pSandboxAnalysis LLVMDemangle)