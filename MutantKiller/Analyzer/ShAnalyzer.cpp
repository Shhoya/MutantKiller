#include "../ShInc.h"

#define LOGGING 0
#ifdef _WIN64
#define ALIGNVALUE 8
#else
#define ALIGNVALUE 4
#endif

bool MutantAnalyzer::GetMutationPair()
{
	Log("Parsing caller...\n");
	std::vector<PVOID> CallerVector;

	
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

	LogT("Need analyze function count : %d\n", CallerVector.size());
	auto MutationPair = new std::pair<PVOID, PVOID>[CallerVector.size()/4];

	Log("Classifying mutation function...\n");

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

	MutationCount = count;
	if (MutationCount == 0)
	{
		ErrorHandler("Can't find mutation function\n", -1);
		return false;
	}

	Green;
	LogT("Known mutation function count : %d\n", MutationCount);
	Gray;

	MutationFinal = new std::pair<PVOID, PVOID>[MutationCount];

	Log("Calculating mutation...\n");
	for (int i = 0; i < MutationCount; i++)
	{
		int EndMutation = 0;
		PVOID result[3] = { nullptr, };
		auto NextRegion = MutationPair[i].second;
#ifdef _WIN64
		DWORD64 StartAddress = (DWORD64)MutationPair[i].second;
#else
		DWORD StartAddress = (DWORD)MutationPair[i].second;
#endif

#if LOGGING
		Log("Caller : %p\tMutation Start : %p\n", MutationPair[i].first, MutationPair[i].second);
#endif
		PVOID JmpAddress = GetEndAddress(StartAddress);
		DWORD RegionSize = (DWORD64)CalcOffset(JmpAddress, 5) - (DWORD64)MutationPair[i].second;
		while (true)
		{
			int offset = 0;
#ifdef _WIN64
			DWORD64 TempNext = (DWORD64)NextRegion;
#else
			DWORD TempNext = (DWORD)NextRegion;
#endif
			JmpAddress = GetEndAddress((DWORD64)NextRegion);

			if (JmpAddress == (PVOID)-1 || JmpAddress == nullptr) { break; }
			if (bReturn == true)
			{
#ifdef _WIN64
				DWORD RegionSize = (DWORD64)JmpAddress - (DWORD64)NextRegion;
#else
				DWORD RegionSize = (DWORD)JmpAddress - (DWORD)TempNext;
#endif
				MutationCalculator(NextRegion, RegionSize, result);
				bReturn = false;
				break;
			}
#ifdef _WIN64
			DWORD RegionSize = (DWORD64)CalcOffset(JmpAddress, 5) - (DWORD64)NextRegion;
#else
			DWORD RegionSize = (DWORD)CalcOffset(JmpAddress, 5) - (DWORD)TempNext;
#endif
			MutationCalculator(NextRegion, RegionSize, result);
			memcpy(&offset, CalcOffset(JmpAddress, 1), 4);
			NextRegion = CalcOffset(JmpAddress, offset + 5);
		}

#ifdef _WIN64

		auto KeyAddress = (DWORD64*)((DWORD64)result[0] + (DWORD64)result[1]);

		DWORD64 MutationResult = GetMutationResult(KeyAddress, (DWORD64)result[2]);
		MutationFinal[i].first = MutationPair[i].first;
		MutationFinal[i].second = (PVOID)MutationResult;
#else
		
		auto KeyAddress = (DWORD*)(((DWORD)result[0] + BaseDiff) + (DWORD)result[1]);
		DWORD MutationResult = GetMutationResult(KeyAddress, (DWORD)result[2]);
		MutationFinal[i].first = MutationPair[i].first;
		MutationFinal[i].second = (DWORD*)MutationResult;
#endif
	}
	
	delete[] MutationPair;
	return true;
}

void MutantAnalyzer::SetMutationMap()
{
	Log("Set Mutation..\n");

	std::multiset<std::pair<std::string, std::string>> SymbolSet;
	MuaCountMap.clear();
	MuaCallerMap.clear();
	MuaDllMap.clear();
	DllNameList.clear();
	ImportCount = 0;

	std::string SymbolName;

	for (int i = 0; i < MutationCount; i++)
	{
		std::pair<std::string, char*> SymName;

		if (ProcessId == SYSTEM_PROCESS)
		{
			SymName = GetKernelSymbolName(MutationFinal[i].second);
			if (SymName.first != "NULL")
			{
				SymbolName = SymName.second;
				SymbolSet.insert(make_pair(SymName.first, SymbolName));
				MuaCallerMap.insert(make_pair(SymbolName, MutationFinal[i].first));
				SymbolName.clear();
			}
		}
		else
		{
			SymName = GetSymbolName(MutationFinal[i].second);
			if (SymName.first != "NULL")
			{
				SymbolName = SymName.second;
				SymbolSet.insert(make_pair(SymName.first, SymbolName));
				MuaCallerMap.insert(make_pair(SymbolName, MutationFinal[i].first));
				SymbolName.clear();
			}
		}
	}

	std::string PreValue;

	for (auto v : SymbolSet)
	{
		if (PreValue == v.second)
		{
			continue;
		}
		PreValue = v.second;
		MuaDllMap.insert(make_pair(v.first, v.second));
	}

	for (auto v : MuaDllMap)
	{
		MuaCountMap.insert(make_pair(v.first, MuaDllMap.count(v.first)));
	}

	for (auto v : MuaCountMap)
	{
		DllNameList.push_back(v.first);
		ImportCount += v.second;
	}

#if LOGGING
	for (auto c : MuaCallerMap)
	{
		Log("%s : %p\n", c.first.c_str(), c.second);
	}

	for (auto d : MuaDllMap)
	{
		Log("%s : %s\n", d.first.c_str(), d.second.c_str());
	}
#endif
	Log("Data analysis complete  (DLL Name : Import count)\n");
	for (auto c : MuaCountMap)
	{
		Green;
		LogT("%s : %d\n", c.first.c_str(), c.second);
		Gray;
	}

}

void MutantAnalyzer::MutationCalculator(PVOID StartAddress, ULONG Size, PVOID Result)
{
	int count = 0;
	std::string Disassm;
	auto Buffer = new BYTE[Size];
	memcpy(Buffer, (PVOID)StartAddress, Size);
#ifdef _WIN64
	DWORD64 Address = (DWORD64)StartAddress;
	DWORD64* result = (DWORD64*)Result;
#else
	DWORD Address = (DWORD)StartAddress;
	DWORD* result = (DWORD*)Result;

#endif
	ZyanUSize Offset = 0;
	const ZyanUSize Length = Size;
	ZydisDecodedInstruction Instruction;
	while (ZYAN_SUCCESS(ZydisDecoderDecodeBuffer(&ZyDecoder, Buffer + Offset, Length - Offset, &Instruction)))
	{
		Disassm.clear();
		char TempBuffer[256] = { 0, };
		ZydisFormatterFormatInstruction(&ZyFormatter, &Instruction, TempBuffer, sizeof(TempBuffer), Address);

		Disassm = std::string(TempBuffer);
#ifdef _WIN64
		if (Disassm.find("lea", 0) != std::string::npos && Instruction.length == 7)
		{
			if (Disassm.find("[0x0000", 0) != std::string::npos)
			{
				DWORD RelOffset = 0;
				memcpy(&RelOffset, (PVOID)(Address + 3), 4);
				DWORD64 RelAddress = (DWORD64)CalcOffset((PVOID)Address, RelOffset + 7);
				result[0] = RelAddress;
			}
			else
			{
				memcpy(&result[2], (PVOID)(Address + 3), 4);
			}
			count++;
#if LOGGING
			Green;
			LogT("%s\n", TempBuffer);
			Gray;
#endif
		}

		if (Disassm.find("mov", 0) != std::string::npos && Disassm.find("[", 0) != std::string::npos && Instruction.length ==7)
		{
			memcpy(&result[1], (PVOID)(Address + 3), 4);
			count++;
#if LOGGING
			Green;
			LogT("%s\n", TempBuffer);
			Gray;
#endif

		}
#else
		if (Disassm.find("mov",0) != std::string::npos && Instruction.length == 5)
		{
			DWORD RelAddress = 0;
			memcpy(&RelAddress, (PVOID)(Address + 1), 4);

			if (NtHeadersPtr->OptionalHeader.ImageBase < RelAddress && NtHeadersPtr->OptionalHeader.ImageBase + NtHeadersPtr->OptionalHeader.SizeOfImage > RelAddress)
			{
				result[0] = RelAddress;
				count++;
#if LOGGING
				Green;
				LogT("%s\n", TempBuffer);
				Gray;
#endif
			}
		}

		if (Disassm.find("mov", 0) != std::string::npos && Disassm.find("[", 0) != std::string::npos && Instruction.length == 6)
		{
			DWORD RelAddress = 0;
			memcpy(&RelAddress, (PVOID)(Address + 2), 4);
			result[1] = RelAddress;
			count++;
#if LOGGING
			Green;
			LogT("%s\n", TempBuffer);
			Gray;
#endif
		}

		if (Disassm.find("lea", 0) != std::string::npos && Disassm.find("[", 0) != std::string::npos && Instruction.length == 6)
		{
			DWORD RelAddress = 0;
			memcpy(&RelAddress, (PVOID)(Address + 2), 4);
			result[2] = RelAddress;
			count++;
#if LOGGING
			Green;
			LogT("%s\n", TempBuffer);
			Gray;
#endif
		}
#endif
		Offset += Instruction.length;
		Address += Instruction.length;
	}

	delete[] Buffer;
}

void MutantAnalyzer::SetFixData()
{
	Log("Setting fix data...\n");

	ULONG Result = 0;
	ULONG StringSize = 0;
	ImportDescSize = (DllNameList.size() + 1) * sizeof(IMAGE_IMPORT_DESCRIPTOR);
	ImportThunkSize = ((DllNameList.size() * 8) + (ImportCount * 8)) * 2;
	for (auto d : DllNameList)
	{
		StringSize += d.length() + 1;
		ImportDllNameSize += d.length() + 1;
	}

	for (auto d : MuaDllMap)
	{
		StringSize += d.second.length() + 3;
	}

	Result = StringSize + ImportDescSize + ImportThunkSize;

	auto DosHeader = (PIMAGE_DOS_HEADER)RelocVa;
	auto NtHeader = (PIMAGE_NT_HEADERS)CalcOffset(DosHeader, DosHeader->e_lfanew);
	auto SectionHeader = IMAGE_FIRST_SECTION(NtHeader);

	ULONG FileAlign = NtHeader->OptionalHeader.FileAlignment;
	ULONG VirtualAlign = NtHeader->OptionalHeader.SectionAlignment;
	VirtualAddress = SectionHeader[NtHeader->FileHeader.NumberOfSections - 1].VirtualAddress +
		SectionHeader[NtHeader->FileHeader.NumberOfSections - 1].Misc.VirtualSize;
	RawAddress = SectionHeader[NtHeader->FileHeader.NumberOfSections - 1].PointerToRawData +
		SectionHeader[NtHeader->FileHeader.NumberOfSections - 1].SizeOfRawData;
	RawSize = SetAlignment(Result, FileAlign);
	VirtualSize = SetAlignment(RawSize, VirtualAlign);
	
	Log("Complete fix data\n");
	Green;
	LogT("New IAT VirtualAddress : %p\n", VirtualAddress);
	LogT("New IAT VirtualSize: %X\n", VirtualSize);
	LogT("New IAT RawAddress : %p\n", RawAddress);
	LogT("New IAT RawSize : %X\n", RawSize);
	Gray;
}

bool MutantAnalyzer::FixDataAlloc()
{
	Log("Setting New IAT data...\n");

	VirtualFree(RelocVa, 0, MEM_RELEASE);
	auto DosHeader = (PIMAGE_DOS_HEADER)TempFileVa;
	auto NtHeader = (PIMAGE_NT_HEADERS)CalcOffset(DosHeader, DosHeader->e_lfanew);
	auto SectionHeader = IMAGE_FIRST_SECTION(NtHeader);
	DWORD SectionCount = NtHeader->FileHeader.NumberOfSections;
	DWORD NewSectionCount = SectionCount + 1;

	DWORD IatSize = VirtualAddress + VirtualSize;
	DWORD Diff = 0;
	FixVa = VirtualAlloc(RelocVa, IatSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (FixVa == nullptr)
	{
		if (GetLastError() == ERROR_INVALID_ADDRESS)
		{
			FixVa = VirtualAlloc(nullptr, IatSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
			Diff = (DWORD64)FixVa - (DWORD64)RelocVa;
		}
		else
		{
			ErrorHandler("Can't allocate memory", GetLastError());
			return false;
		}
	}

	memset(FixVa, 0, IatSize);
	memcpy(FixVa, TempFileVa, NtHeader->OptionalHeader.SizeOfHeaders);
	
	auto FixDosHeader = (PIMAGE_DOS_HEADER)FixVa;
	auto FixNtHeader = (PIMAGE_NT_HEADERS)CalcOffset(FixDosHeader, FixDosHeader->e_lfanew);
	auto FixSectionHeader = IMAGE_FIRST_SECTION(FixNtHeader);

	for (int i = 0; i < SectionCount; i++)
	{
		auto FixVirtualAddress = CalcOffset(FixVa, FixSectionHeader[i].VirtualAddress);
		auto FixFromRawData = CalcOffset(TempFileVa, FixSectionHeader[i].PointerToRawData);
		memcpy(FixVirtualAddress, FixFromRawData, FixSectionHeader[i].SizeOfRawData);
	}

	FixNtHeader->OptionalHeader.SizeOfImage = SetAlignment(IatSize, FixNtHeader->OptionalHeader.SectionAlignment);
	FixNtHeader->FileHeader.NumberOfSections = NewSectionCount;
	strcpy((char*)FixSectionHeader[NewSectionCount-1].Name, ".ShIAT");
	FixSectionHeader[NewSectionCount - 1].VirtualAddress = VirtualAddress;
	FixSectionHeader[NewSectionCount - 1].Misc.VirtualSize = VirtualSize;
	FixSectionHeader[NewSectionCount - 1].PointerToRawData = RawAddress;
	FixSectionHeader[NewSectionCount - 1].SizeOfRawData = RawSize;
	FixSectionHeader[NewSectionCount - 1].Characteristics = IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ;

	FixNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress = VirtualAddress;
	FixNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size = ImportDescSize;

	auto ImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)CalcOffset(FixVa, VirtualAddress);
	auto ThunkStart = (DWORD*)CalcOffset(FixVa, VirtualAddress + ImportDescSize);
	auto DllNameStart = CalcOffset(FixVa, VirtualAddress + ImportDescSize + ImportThunkSize);
	auto ImportNameStart = CalcOffset(DllNameStart, ImportDllNameSize + ALIGNVALUE);

	for (auto c : MuaCountMap)
	{
		ULONG ImportStringSize = 0;
		ImportDescriptor->OriginalFirstThunk = (DWORD)CalcOffset(ThunkStart, (int)FixVa, true);
		ImportDescriptor->Name = (DWORD)CalcOffset(DllNameStart, (int)FixVa, true);
		ImportDescriptor->FirstThunk = ImportDescriptor->OriginalFirstThunk;

		auto Name = (char*)CalcOffset(FixVa, ImportDescriptor->Name);
		strcpy(Name, c.first.c_str());
		for (auto dll : MuaDllMap)
		{
			if (c.first == dll.first)
			{
				auto NameStart = (char*)CalcOffset(ImportNameStart,2);
				int NameLength = dll.second.length() + 1;
				strncpy(NameStart, dll.second.c_str(), NameLength);
				*ThunkStart = (DWORD)CalcOffset(ImportNameStart, (int)FixVa, true);
				for (auto caller : MuaCallerMap)
				{
					if (dll.second == caller.first)
					{
						int offset = (DWORD64)ThunkStart - (Diff + (DWORD64)caller.second);
						DWORD Operand = offset - 5;
						memcpy(CalcOffset(caller.second,Diff+1), &Operand, 4);
					}
				}
				ThunkStart = (DWORD*)CalcOffset(ThunkStart, ALIGNVALUE);
				ImportNameStart = CalcOffset(ImportNameStart, dll.second.length() + 3);
			}
		}
		ThunkStart = (DWORD*)CalcOffset(ThunkStart, ALIGNVALUE);
		ImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)CalcOffset(ImportDescriptor, sizeof(IMAGE_IMPORT_DESCRIPTOR));
		DllNameStart = CalcOffset(DllNameStart, c.first.length() + 1);
	}
	Green;
	LogT("New IAT data setup complete\n\n");
	Gray;
	return true;
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

PVOID MutantAnalyzer::GetEndAddress64(DWORD64 StartAddress)
{
	std::string Disassm;
	auto Buffer = new BYTE[0x40];
	memcpy(Buffer, (PVOID)StartAddress, 0x40);
	bool bLastupdated = false;
	ZyanUSize Offset = 0;
	const ZyanUSize Length = 0x40;
	ZydisDecodedInstruction Instruction;
	while (ZYAN_SUCCESS(ZydisDecoderDecodeBuffer(&ZyDecoder, Buffer + Offset, Length - Offset, &Instruction)))
	{
		Disassm.clear();
		char TempBuffer[256] = { 0, };
		ZydisFormatterFormatInstruction(&ZyFormatter, &Instruction, TempBuffer, sizeof(TempBuffer), StartAddress);

		Disassm = std::string(TempBuffer);
		if (Disassm.find("mov",0) != std::string::npos && Instruction.length == 7)
		{
			bLastupdated = true;
		}
		if (Disassm.find("lea", 0) != std::string::npos && Instruction.length == 7)
		{
			bLastupdated = true;
		}
		if (Disassm.find("ret",0) != std::string::npos)
		{
			if (bLastupdated == true)
			{
				bReturn = true;
				delete[] Buffer;
				return (PVOID)StartAddress;
			}
			delete[] Buffer;
			return (PVOID)-1;
		}

		if (Disassm.find("jmp", 0) != std::string::npos)
		{
			BYTE FirstByte[1] = { 0, };
			memcpy(FirstByte, (PVOID)StartAddress, 1);
			if (FirstByte[0] == 0xE9)
			{
				delete[] Buffer;
				return (PVOID)StartAddress;
			}
		}
		Offset += Instruction.length;
		StartAddress += Instruction.length;
	}

	delete[] Buffer;
	return nullptr;
}

PVOID MutantAnalyzer::GetEndAddress32(DWORD StartAddress)
{
	std::string Disassm;
	auto Buffer = new BYTE[0x40];
	memcpy(Buffer, (PVOID)StartAddress, 0x40);
	bool bLastupdated = false;
	ZyanUSize Offset = 0;
	const ZyanUSize Length = 0x40;
	ZydisDecodedInstruction Instruction;
	while (ZYAN_SUCCESS(ZydisDecoderDecodeBuffer(&ZyDecoder, Buffer + Offset, Length - Offset, &Instruction)))
	{
		Disassm.clear();
		char TempBuffer[256] = { 0, };
		ZydisFormatterFormatInstruction(&ZyFormatter, &Instruction, TempBuffer, sizeof(TempBuffer), StartAddress);

		Disassm = std::string(TempBuffer);
		if (Disassm.find("mov", 0) != std::string::npos && Instruction.length == 7)
		{
			bLastupdated = true;
		}
		if (Disassm.find("lea", 0) != std::string::npos && Instruction.length == 7)
		{
			bLastupdated = true;
		}
		if (Disassm.find("ret", 0) != std::string::npos)
		{
			if (bLastupdated == true)
			{
				bReturn = true;
				delete[] Buffer;
				return (PVOID)StartAddress;
			}
			delete[] Buffer;
			return (PVOID)-1;
		}

		if (Disassm.find("jmp", 0) != std::string::npos)
		{
			BYTE FirstByte[1] = { 0, };
			memcpy(FirstByte, (PVOID)StartAddress, 1);
			if (FirstByte[0] == 0xE9)
			{
				delete[] Buffer;
				return (PVOID)StartAddress;
			}
		}
		Offset += Instruction.length;
		StartAddress += Instruction.length;
	}

	delete[] Buffer;
	return nullptr;
}

DWORD64 MutantAnalyzer::GetMutationResult64(DWORD64* Address, DWORD64 Offset)
{
	DWORD64 Result = 0;
	__try {
		
		Result = *Address + Offset;
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		Result = 0;
	}
	return Result;
}

DWORD MutantAnalyzer::GetMutationResult32(DWORD* Address, DWORD Offset)
{
	DWORD Result = 0;
	__try {
		Result = *Address + Offset;
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		Result = 0;
	}
	return Result;
}

char* MutantAnalyzer::FixDump(char* DumpData, DWORD* ReturnLength)
{
	auto DosHeader = (PIMAGE_DOS_HEADER)DumpData;
	auto NtHeader = (PIMAGE_NT_HEADERS)CalcOffset(DosHeader, DosHeader->e_lfanew);
	auto SectionHeader = (PIMAGE_SECTION_HEADER)((DWORD64)&NtHeader->OptionalHeader + NtHeader->FileHeader.SizeOfOptionalHeader);
	ULONG SectionAlign = NtHeader->OptionalHeader.SectionAlignment;
	ULONG FileAlign = NtHeader->OptionalHeader.FileAlignment;
	ULONG FileSize = 0, HeaderSize = 0;

	HeaderSize = NtHeader->OptionalHeader.SizeOfHeaders;
	FileSize = SectionHeader[NtHeader->FileHeader.NumberOfSections - 1].PointerToRawData + SectionHeader[NtHeader->FileHeader.NumberOfSections - 1].SizeOfRawData;
	

	*ReturnLength = FileSize;
	auto FixData = new char[FileSize];

	// PE Section header fix complete
	memcpy(FixData, DumpData, HeaderSize);
	for (int i = 0; i < NtHeader->FileHeader.NumberOfSections; i++)
	{
		auto StartVa = CalcOffset(DumpData, SectionHeader[i].VirtualAddress, false);
		memcpy(CalcOffset(FixData, SectionHeader[i].PointerToRawData, false), StartVa, SectionHeader[i].SizeOfRawData);
	}
	return FixData;
}

bool MutantAnalyzer::InitializeData(std::string Path, int Pid)
{
	ProcessId = Pid;
	TargetFilePath = Path;

	if (ProcessId == 4)
	{
		Log("Getting system module information...\n");
		HMODULE NtModule = GetModuleHandle("ntdll.dll");
		NtQuerySystemInformation_t NtQuerySystemInformation = (NtQuerySystemInformation_t)GetProcAddress(NtModule, "NtQuerySystemInformation");
		if (NtQuerySystemInformation == nullptr)
		{
			ErrorHandler("Can't get NtQuerySystemInformation procedure", GetLastError());
			return false;
		}

		PVOID Buffer = nullptr;
		DWORD ReturnLength = 0;
		ULONG Status = NtQuerySystemInformation(0xb, nullptr, 0, &ReturnLength);
		if (Status == 0xC0000004)
		{
			Buffer = VirtualAlloc(nullptr,0x400*0x400, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
			memset(Buffer, 0, 0x400*0x400);
			Status = NtQuerySystemInformation(0xb, Buffer, ReturnLength, &ReturnLength);
		}

		if (Status != 0)
		{
			ErrorHandler("Can't get kernel module information", Status);
			return false;
		}
		SYSTEM_MODULE_INFORMATION* ModInfo = (SYSTEM_MODULE_INFORMATION*)Buffer;
		for (int i = 0; i < ModInfo->ModuleCount; i++)
		{
			if (strstr(ModInfo->Modules[i].FullPathName, "ntoskrnl.exe"))
			{
				Ntoskrnl = ModInfo->Modules[i].ImageBase;
				break;
			}
		}
		if (Ntoskrnl == 0)
		{
			ErrorHandler("Can't set ntosknrl base", -1);
			return false;
		}
	}

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
	NtHeadersPtr = NtHeaders;
	if (DosHeader->e_magic != IMAGE_DOS_SIGNATURE || NtHeaders->Signature != IMAGE_NT_SIGNATURE)
	{
		ErrorHandler("Invalid PE format", -1);
		return false;
	}

	Log("Relocating dump file...\n");
	RelocVa = VirtualAlloc((PVOID)NtHeaders->OptionalHeader.ImageBase, NtHeaders->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (RelocVa == nullptr)
	{
		if (GetLastError() == ERROR_INVALID_ADDRESS || GetLastError() == ERROR_INVALID_PARAMETER)
		{
			RelocVa = VirtualAlloc(nullptr, NtHeaders->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
#ifdef _WIN64
			BaseDiff = (DWORD64)RelocVa - NtHeaders->OptionalHeader.ImageBase;
#else
			BaseDiff = (DWORD)RelocVa - NtHeaders->OptionalHeader.ImageBase;
#endif
		}
		else
		{
			ErrorHandler("Can't allocate memory", GetLastError());
			return false;
		}
	}


	RelocVaEnd = CalcOffset(RelocVa, NtHeaders->OptionalHeader.SizeOfImage);
	InfoLog("Reloc V.A", RelocVa);
	InfoLog("Reloc V.A End", RelocVaEnd);
	InfoLog("Original", (PVOID)NtHeaders->OptionalHeader.ImageBase);

	memcpy(RelocVa, TempFileVa, NtHeaders->OptionalHeader.SizeOfHeaders);
	PIMAGE_SECTION_HEADER SectionHeader = IMAGE_FIRST_SECTION(NtHeaders);
	
	if (SectionHeader[0].PointerToRawData == 0)
	{
		ErrorHandler("It is not a file dump file", -1);
		return false;
	}

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

#ifdef _WIN64
	ZydisDecoderInit(&ZyDecoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_ADDRESS_WIDTH_64);
#else
	ZydisDecoderInit(&ZyDecoder, ZYDIS_MACHINE_MODE_LONG_COMPAT_32, ZYDIS_ADDRESS_WIDTH_32);
#endif
	ZydisFormatterInit(&ZyFormatter, ZYDIS_FORMATTER_STYLE_INTEL);

	Blue;
	Log("Initialize Data Complete\n\n");
	Gray;
	return true;
}

void MutantAnalyzer::Analyzer()
{
	if (GetMutationPair() == false)
	{
		return;
	}
	Green;
	LogT("Calculation Complete\n");
	Gray;
	
	if (SymbolInit() == true)
	{
#ifdef _WIN64
		if (ProcessId == 4)
		{
			SymbolDownload();
		}
#endif
		SetMutationMap();
		SetFixData();
		if(FixDataAlloc() == false)
		{
			return;
		}
		ULONG ret = 0;
		auto FixData = FixDump((char*)FixVa, &ret);
		auto Path = std::filesystem::path(TargetFilePath);
		std::ofstream FileStream(TargetFilePath + "_fix" + Path.extension().string(), std::ios::binary);
		FileStream.write(FixData, ret);
		FileStream.close();

		
		Blue;
		Log("Save File Complete (https://shhoya.github.io)\n");
		Gray;
	}
}

PVOID MutantAnalyzer::CalcOffset(PVOID Address, int Offset, bool bMinus)
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

DWORD64 MutantAnalyzer::SetAlignment(ULONG64 Original, ULONG Alignment)
{
	return ((Original + Alignment - 1) / Alignment) * Alignment;
}

ShSymbols::~ShSymbols()
{
	if (ProcessHandle != nullptr)
	{
		SymCleanup(ProcessHandle);
	}
}

bool ShSymbols::SymbolInit(ULONG Pid)
{
	if (Pid)
	{
		ProcessId = Pid;
		ProcessHandle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, false, ProcessId);
	}
	Log("Setting symbol information\n");
	bool bInvadeProcess = ProcessId == 4 ? false : true;
	GetCurrentDirectory(MAX_PATH, SymbolDir);
	if (SymbolDir == nullptr)
	{
		ErrorHandler("Can't get current directory", GetLastError());
		return false;
	}

	strcat(SymbolDir, "\\Symbols\\");
	auto SymbolPath = std::filesystem::path(SymbolDir);
	if (std::filesystem::exists(SymbolPath) == false)
	{
		std::filesystem::create_directory("Symbols");
	}

	strcpy(SymchkArguments, "/s SRV*");
	strcat(SymchkArguments, SymbolDir);
	strcat(SymchkArguments, "*http://msdl.microsoft.com/download/symbols");

	if (bInvadeProcess == false)
	{
		SymSetOptions(SYMOPT_EXACT_SYMBOLS | SYMOPT_CASE_INSENSITIVE);
	}
	else
	{
		SymSetOptions(SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS);
	}

	if (ProcessHandle == nullptr || ProcessHandle == INVALID_HANDLE_VALUE)
	{
		ErrorHandler("Invalid process handle", -1);
		return false;
	}

	if (SymInitialize(ProcessHandle, SymbolDir, bInvadeProcess) == false)
	{
		ErrorHandler("Can't initialize symbol", GetLastError());
		return false;
	}
	
	return true;
}

void ShSymbols::SymbolDownload()
{
	if (strlen(SymbolDir) != 0)
	{
		bool bFound = false;
		Log("Downloading Symbols...\n");
		std::string CommandLine = std::string(SymbolDir) + "symchk.exe C:\\Windows\\system32\\ntoskrnl.exe " + std::string(SymchkArguments);
		WinExec(CommandLine.c_str(), SW_HIDE);
		while (true)
		{
			if (bFound)
			{
				break;
			}
			auto SymPath = std::filesystem::path(SymbolDir);
			for (auto& p : std::filesystem::recursive_directory_iterator(SymPath))
			{
				if (std::filesystem::is_directory(p.path()) == false)
				{
					if (p.path().extension() == ".pdb")
					{
						Sleep(1000);
						bFound = true;
						break;
					}
				}
			}
		}
		printf("\n");
	}
	else
	{
		ErrorHandler("Can't symbol download\n", -1);
	}
}

std::pair<std::string, char*> ShSymbols::GetKernelSymbolName(PVOID Address)
{
	std::pair<std::string, char*> Result;
	IMAGEHLP_SYMBOL64* pSym = NULL;
	char buffer[sizeof(IMAGEHLP_SYMBOL64) + MAX_SYM_NAME * sizeof(TCHAR)] = { 0 };
	pSym = (IMAGEHLP_SYMBOL64*)buffer;

	pSym->SizeOfStruct = sizeof(IMAGEHLP_SYMBOL64);
	pSym->MaxNameLength = MAX_PATH;
	DWORD64 dwDisplacement64 = 0;

	IMAGEHLP_MODULEW64 pMod = { 0, };
	pMod.SizeOfStruct = sizeof(IMAGEHLP_MODULEW64);

	char FilePath[MAX_PATH] = { 0, };
	DWORD64 BaseAddress = 0;

	strcpy(FilePath, "C:\\Windows\\System32\\ntoskrnl.exe");
	BaseAddress = (DWORD64)Ntoskrnl;

	HANDLE hFile = CreateFile("C:\\Windows\\System32\\ntoskrnl.exe", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
	if (hFile == nullptr || hFile == INVALID_HANDLE_VALUE) {
		ErrorHandler("Can't open file", GetLastError());
		Result.first = "NULL";
		return Result;
	}

	SymLoadModuleEx(ProcessHandle, hFile, "kernel", "kernel", BaseAddress, 0, nullptr, 0);
	bool result = SymGetModuleInfoW64(ProcessHandle, (DWORD64)Address, &pMod);
	if (result == true)
	{
		result = SymGetSymFromAddr64(ProcessHandle, (DWORD64)Address, &dwDisplacement64, pSym);
		if (result == true)
		{
			Result.first = "ntoskrnl";
			Result.second = pSym->Name;
			CloseHandle(hFile);
			return Result;
		}
	}
	CloseHandle(hFile);
	Result.first = "NULL";
	return Result;
}

std::pair<std::string, char*> ShSymbols::GetSymbolName(PVOID Address)
{
	std::pair<std::string, char*> Result;
#ifdef _WIN64
	DWORD64 TargetAddress = (DWORD64)Address;
	DWORD64 Displacement = 0;
#else
	DWORD TargetAddress = (DWORD)Address;
	DWORD Displacement = 0;
#endif

	PIMAGEHLP_SYMBOL pSymbol = nullptr;
	IMAGEHLP_MODULE SymModule = { 0, };

	char Buffer[sizeof(IMAGEHLP_SYMBOL) + MAX_SYM_NAME * sizeof(CHAR)] = { 0, };
	pSymbol = (PIMAGEHLP_SYMBOL)Buffer;

	pSymbol->SizeOfStruct = sizeof(IMAGEHLP_SYMBOL);
	pSymbol->MaxNameLength = MAX_PATH;

	SymModule.SizeOfStruct = sizeof(IMAGEHLP_MODULE);

	bool result = SymGetModuleInfo(ProcessHandle, TargetAddress, &SymModule);
	if (result == true)
	{
		HANDLE FileHandle = CreateFile(SymModule.ImageName, GENERIC_ALL, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
		SymLoadModuleEx(ProcessHandle, FileHandle, nullptr, nullptr, SymModule.BaseOfImage, SymModule.ImageSize, nullptr, 0);
		SymGetSymFromAddr(ProcessHandle, TargetAddress, &Displacement, pSymbol);
		auto Path = std::filesystem::path(SymModule.ImageName);
		std::string DllName = Path.filename().string();
		Result.first = DllName;
		Result.second = pSymbol->Name;
		return Result;
	}
	Result.first = "NULL";
	return Result;
}
