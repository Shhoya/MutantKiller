#include "../ShInc.h"

bool MutantAnalyzer::GetMutationPair()
{
	Log("Parsing caller...\n");
	std::vector<PVOID> CallerVector;

	auto MutationPair = new std::pair<PVOID, PVOID>[0x1000];
	for (auto s : SectionVector)
	{
		StartVa = CalcOffset(RelocVa, s.VirtualAddress);
		RawDataSize = s.SizeOfRawData;
		std::vector<PVOID> Caller = GetCallerAddress();
		for (auto c : Caller)
		{
			CallerVector.push_back(c);
		}
	}
	LogT("Need analyze function count : %d", CallerVector.size());
	
	int count = 0;
	for (auto c : CallerVector)
	{
		int Offset = 0;
		memcpy(&Offset, CalcOffset(c, 1), 4);
		auto CalleeAddr = CalcOffset(c, Offset + 5);
		if ((DWORD64)CalleeAddr < (DWORD64)RelocVa || (DWORD64)CalleeAddr >(DWORD64)RelocVaEnd)
		{
			continue;
		}

		auto TempAddr = PatternScan("\xE9\x00\x00\x00\x00", "x????", (char*)CalleeAddr, 0x20);
		if (TempAddr == 0) { continue; }
		BYTE CompareByte[1] = { 0, };
		memcpy(CompareByte, CalleeAddr, 1);
		if (CompareByte[0] != 0x90) { continue; }

		MutationPair[count].first = c;
		MutationPair[count].second = CalleeAddr;
		count++;
	}

	ULONG MutationCount = count;
	
	
	

	return false;
}

std::vector<PVOID> MutantAnalyzer::GetCallerAddress()
{
	ULONG ReadSize = RawDataSize;
	std::vector<PVOID> result;
	while (true)
	{
		auto TempAddr = (PVOID)PatternScan("\xE8\x00\x00\x00\x00", "x????", (char*)StartVa, ReadSize);
		if (TempAddr == nullptr) { break; }
		
		ULONG RelValue = *(PDWORD)CalcOffset(TempAddr, 1);
		PVOID TestValue = CalcOffset(TempAddr, RelValue + 5);
		SIZE_T RetValue = 0;
		BYTE TempBuffer[4] = { 0, };
		
		if (ReadProcessMemory(GetCurrentProcess(), TestValue, TempBuffer, 4, &RetValue) == false)
		{
			StartVa = CalcOffset(TempAddr, 1);
			continue;
		}

		result.push_back(TempAddr);
		StartVa = CalcOffset(TempAddr, 5);
#ifdef _WIN64
		int Offset = ((DWORD64)StartVa - (DWORD64)RelocVa);
		Offset -= 0x1000;
#else
		int Offset = (ULONG)StartVa - (ULONG)RelocVa;
		Offset -= 0x1000;
#endif
		ReadSize = RawDataSize - Offset;
	}
	return result;
}

bool MutantAnalyzer::InitializeData(std::string Path, int Pid)
{
	Log("Getting dump file handle...\n");
	DumpHandle = CreateFile(Path.c_str(), GENERIC_READ, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
	if (DumpHandle == INVALID_HANDLE_VALUE)
	{
		ErrorHandler("Can't get handle", GetLastError());
		return false;;
	}

	Log("Getting process handle...\n");
	ProcessHandle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, false, Pid);
	if (ProcessHandle==nullptr)
	{
		ErrorHandler("Can't get handle", GetLastError());
		return false;
	}

	Log("Getting file information...\n");
	BY_HANDLE_FILE_INFORMATION FileInfo = { 0, };
	if (GetFileInformationByHandle(DumpHandle, &FileInfo) == false)
	{
		ErrorHandler("Can't get file information", GetLastError());
		return false;
	}

	if (FileInfo.nFileSizeHigh != 0 || FileInfo.nFileSizeLow == 0)
	{
		ErrorHandler("Big size file or zero file size", GetLastError());
		return false;
	}

	Log("Virtual memory is allocated...\n");
	ULONG Size = FileInfo.nFileSizeLow;
	TempFileVa = VirtualAlloc(nullptr, Size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (TempFileVa == nullptr)
	{
		ErrorHandler("Can't allocate memory", GetLastError());
		return false;
	}
	InfoLog("File V.A", TempFileVa);

	Log("Reading dump file...\n");
	if (ReadFile(DumpHandle, TempFileVa, Size, nullptr, nullptr) == false)
	{
		ErrorHandler("Can't read dump file", GetLastError());
		return false;
	}

	Log("Checking signature...\n");
	auto DosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(TempFileVa);
	auto NtHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(CalcOffset(DosHeader, DosHeader->e_lfanew));
	
	if (DosHeader->e_magic != IMAGE_DOS_SIGNATURE || NtHeaders->Signature != IMAGE_NT_SIGNATURE)
	{
		ErrorHandler("Invalid PE format", -1);
		return false;
	}

	Log("Relocating dump file...\n");
	RelocVa = VirtualAlloc((PVOID)NtHeaders->OptionalHeader.ImageBase, NtHeaders->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (RelocVa == nullptr)
	{
		ErrorHandler("Can't allocate memory", GetLastError());
		return false;
	}
	InfoLog("Reloc V.A", RelocVa);


	RelocVaEnd = CalcOffset(RelocVa, NtHeaders->OptionalHeader.SizeOfImage);

	memcpy(RelocVa, TempFileVa, NtHeaders->FileHeader.SizeOfOptionalHeader);
	PIMAGE_SECTION_HEADER SectionHeader = IMAGE_FIRST_SECTION(NtHeaders);
	for (int i = 0; i < NtHeaders->FileHeader.NumberOfSections; i++)
	{
		auto VirtualAddress = CalcOffset(RelocVa, SectionHeader[i].VirtualAddress);
		auto FromRawData = CalcOffset(TempFileVa, SectionHeader[i].PointerToRawData);
		memcpy(VirtualAddress, FromRawData, SectionHeader[i].SizeOfRawData);
		if (SectionHeader[i].Characteristics & IMAGE_SCN_MEM_EXECUTE)
		{
			SectionVector.push_back(SectionHeader[i]);
		}
	}

	Blue;
	Log("Complete Initialize Data\n\n");
	Gray;
	return true;
}

void MutantAnalyzer::Analyzer()
{
	if (GetMutationPair())
	{

	}
}

PVOID MutantAnalyzer::CalcOffset(PVOID Address, ULONG Offset, bool bMinus)
{
	if (bMinus) {
		return (PVOID)((DWORD64)Address - Offset);
	}

	return (PVOID)((DWORD64)Address + Offset);
}

char* MutantAnalyzer::PatternScan(const char* Pattern, const char* Mask, char* Begin, int Size)
{
	intptr_t patternLen = strlen(Mask);

	for (int i = 0; i < Size; i++)
	{
		bool found = true;
		for (int j = 0; j < patternLen; j++)
		{
			if (Mask[j] != '?' && Pattern[j] != *(char*)((intptr_t)Begin + i + j))
			{
				found = false;
				break;
			}
		}
		if (found)
		{
			return (Begin + i);
		}
	}
	return nullptr;
}
