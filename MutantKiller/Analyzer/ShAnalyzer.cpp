#include "../ShInc.h"

#define LOGGING 0

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
	LogT("Need analyze function count : %d\n", CallerVector.size());
	
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

	ULONG MutationCount = count;
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
		auto KeyAddress = (DWORD*)((DWORD)result[0] + (DWORD)result[1]);
		DWORD MutationResult = GetMutationResult(KeyAddress, (DWORD)result[2]);
		MutationFinal[i].first = MutationPair[i].first;
		MutationFinal[i].second = (DWORD*)MutationResult;
#endif




	}
	

	return false;
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
		if (GetLastError() == ERROR_INVALID_ADDRESS)
		{
			RelocVa = VirtualAlloc(nullptr, NtHeaders->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
		}
		else
		{
			ErrorHandler("Can't allocate memory", GetLastError());
			system("pause");
			return false;
		}
	}


	RelocVaEnd = CalcOffset(RelocVa, NtHeaders->OptionalHeader.SizeOfImage);
	InfoLog("Reloc V.A", RelocVa);
	InfoLog("Reloc V.A End", RelocVaEnd);



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

#ifdef _WIN64
	ZydisDecoderInit(&ZyDecoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_ADDRESS_WIDTH_64);
#else
	ZydisDecoderInit(&ZyDecoder, ZYDIS_MACHINE_MODE_LONG_COMPAT_32, ZYDIS_ADDRESS_WIDTH_32);
#endif
	ZydisFormatterInit(&ZyFormatter, ZYDIS_FORMATTER_STYLE_INTEL);

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
