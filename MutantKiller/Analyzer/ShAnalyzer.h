#ifndef _SHANALYZER_H_
#define _SHANALYZER_H_

#pragma comment(lib,"dbghelp.lib")

#define SYSTEM_PROCESS 4

class ShSymbols
{
public:
	~ShSymbols();
	bool SymbolInit(ULONG Pid = 0);
	void SymbolDownload();
	std::pair<std::string, char*> GetKernelSymbolName(PVOID Address);
	std::pair<std::string, char*> GetSymbolName(PVOID Address);

public:
	HANDLE ProcessHandle = nullptr;
	ULONG ProcessId = 0;
	char SymbolDir[MAX_PATH] = { 0, };
	char SymchkArguments[MAX_PATH] = { 0, };
};

class MutantAnalyzer : public ShSymbols
{
#ifdef _WIN64
#define GetEndAddress GetEndAddress64
#define GetMutationResult GetMutationResult64 
#else
#define GetEndAddress GetEndAddress32
#define GetMutationResult GetMutationResult32
#endif


public:
	bool GetMutationPair();
	void SetMutationMap();
	bool IsMutationFunction(PVOID TargetAddress, ULONG Size);
	void MutationCalculator(PVOID StartAddress, ULONG Size, PVOID Result);

	void SetFixData();
	bool FixDataAlloc();
	
	std::vector<PVOID> GetCallerAddress();

	PVOID GetEndAddress64(DWORD64 StartAddress);
	PVOID GetEndAddress32(DWORD StartAddress);
	DWORD64 GetMutationResult64(DWORD64* Address, DWORD64 Offset);
	DWORD GetMutationResult32(DWORD* Address, DWORD Offset);


	bool InitializeData(std::string Path, int Pid);
	void Analyzer();

	PVOID CalcOffset(PVOID Address, int Offset, bool bMinus = false);
	char* PatternScan(const char* Pattern, const char* Mask, char* Begin, int Size);

private:
	ZydisDecoder ZyDecoder;
	ZydisFormatter ZyFormatter;

	HANDLE DumpHandle = nullptr;

	PIMAGE_NT_HEADERS NtHeadersPtr = nullptr;

	PVOID RelocVa = nullptr;
	PVOID RelocVaEnd = nullptr;
	DWORD BaseDiff = 0;
	PVOID StartVa = nullptr;

	PVOID TempFileVa = nullptr;

	ULONG RawDataSize = 0;

	ULONG ImportCount = 0;
	ULONG ImportDescSize = 0;
	ULONG ImportThunkSize = 0;
	ULONG ImportDllNameSize = 0;

	ULONG RawAddress = 0;
	ULONG RawSize = 0;
	ULONG VirtualAddress = 0;
	ULONG VirtualSize = 0;

	ULONG MutationCount = 0;
	bool bReturn = false;

	std::vector<IMAGE_SECTION_HEADER> SectionVector;
	std::pair<PVOID, PVOID>* MutationFinal = nullptr;
	
	std::unordered_map<std::string, int> MuaCountMap;
	std::multimap<std::string, std::string> MuaDllMap;
	std::multimap<std::string, PVOID> MuaCallerMap;
	std::vector<std::string> DllNameList;
};

#endif // !_SHANALYZER_H_
