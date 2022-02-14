#ifndef _SHANALYZER_H_
#define _SHANALYZER_H_

#pragma comment(lib,"dbghelp.lib")

class MutantAnalyzer
{
public:
	bool GetMutationPair();
	void SetMutationMap();
	bool IsMutationFunction(PVOID TargetAddress, ULONG Size);
	int MutationCalculator(PVOID StartAddress, ULONG Size, PVOID Result);

	void SetFixData();
	bool FixDataAlloc();

	std::vector<PVOID> GetCallerAddress();

	bool InitializeData(std::string Path, int Pid);
	void Analyzer();

	PVOID CalcOffset(PVOID Address, ULONG Offset, bool bMinus = false);
	char* PatternScan(const char* Pattern, const char* Mask, char* Begin, int Size);

private:
	HANDLE DumpHandle = nullptr;
	HANDLE ProcessHandle = nullptr;

	PVOID RelocVa = nullptr;
	PVOID RelocVaEnd = nullptr;
	PVOID StartVa = nullptr;

	PVOID TempFileVa = nullptr;

	ULONG RawDataSize = 0;

	ULONG ImportDescSize = 0;
	ULONG ImportThunkSize = 0;
	ULONG ImportDllNameSize = 0;

	ULONG RawAddress = 0;
	ULONG RawSize = 0;
	ULONG VirtualAddress = 0;
	ULONG VirtualSize = 0;

	std::vector<IMAGE_SECTION_HEADER> SectionVector;
	std::unordered_map<std::string, int> MuaCountMap;
	std::multimap<std::string, std::string> MuaDllMap;
	std::multimap<std::string, void*> MuaCallerMap;
	std::vector<std::string> DllNameList;
};

#endif // !_SHANALYZER_H_
