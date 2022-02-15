#include "ShInc.h"

#pragma warning(disable:4996)

int main(int argc, char* argv[])
{
	system("mode con cols=123");
	PrintLogo();
	if (argc != 3)
	{
		PrintHelp();
		return -1;
	}

	auto MuA = new MutantAnalyzer();
	if (MuA->InitializeData(argv[1], atoi(argv[2])) == false)
	{
		ErrLog("Can't initialize\n");
		return -1;
	}

	MuA->Analyzer();

	

	/*ZyanU8 data[] =
	{
		0x51, 0x8D, 0x45, 0xFF, 0x50, 0xFF, 0x75, 0x0C, 0xFF, 0x75,
		0x08, 0xFF, 0x15, 0xA0, 0xA5, 0x48, 0x76, 0x85, 0xC0, 0x0F,
		0x88, 0xFC, 0xDA, 0x02, 0x00
	};

	ZydisDecoder decoder;
	ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_ADDRESS_WIDTH_64);

	ZydisFormatter formatter;
	ZydisFormatterInit(&formatter, ZYDIS_FORMATTER_STYLE_INTEL);

	ZyanU64 runtime_address = 0x007FFFFFFF400000;
	ZyanUSize offset = 0;
	const ZyanUSize length = sizeof(data);
	ZydisDecodedInstruction instruction;
	while (ZYAN_SUCCESS(ZydisDecoderDecodeBuffer(&decoder, data + offset, length - offset,
		&instruction)))
	{
		printf("%016" PRIX64 "  ", runtime_address);

		char buffer[256];
		ZydisFormatterFormatInstruction(&formatter, &instruction, buffer, sizeof(buffer),
			runtime_address);
		puts(buffer);

		offset += instruction.length;
		runtime_address += instruction.length;
	}*/

	return 0;
}

void PrintLogo()
{
	SetConsoleTitle("Mutant Killer");
	
	printf("==========================================================================================================================\n");
	Red;
	printf(" _______  ___   __   __  _______  ___      _______    __   __  __   __  _______  _______  _______  ___   _______  __    _ \n");
	Blue;
	printf("|       ||   | |  |_|  ||       ||   |    |       |  |  |_|  ||  | |  ||       ||   _   ||       ||   | |       ||  |  | |\n");
	Green;
	printf("|  _____||   | |       ||    _  ||   |    |    ___|  |       ||  | |  ||_     _||  |_|  ||_     _||   | |   _   ||   |_| |\n");
	Purple;
	printf("| |_____ |   | |       ||   |_| ||   |    |   |___   |       ||  |_|  |  |   |  |       |  |   |  |   | |  | |  ||       |\n");
	Yellow;
	printf("|_____  ||   | |       ||    ___||   |___ |    ___|  |       ||       |  |   |  |       |  |   |  |   | |  |_|  ||  _    |\n");
	White;
	printf(" _____| ||   | | ||_|| ||   |    |       ||   |___   | ||_|| ||       |  |   |  |   _   |  |   |  |   | |       || | |   |\n");
	Red;
	printf("|_______||___| |_|   |_||___|    |_______||_______|  |_|   |_||_______|  |___|  |__| |__|  |___|  |___| |_______||_|  |__|\n\n");
	White;
	printf("Simply VMP Mutation Analyzer (https://shhoya.github.io)\n");
	Gray;
	printf("==========================================================================================================================\n\n");

}

void PrintHelp()
{
	Log("Usage : MutantKiller.exe <dump file> <target pid>\n");
}

void ErrorHandler(const char* msg, ULONG LastError)
{
	char* FullMsg = new char[256];
	sprintf(FullMsg, "%s : %d", msg, LastError);
	Red;
	ErrLogT("%s\n",FullMsg);
	Gray;
	delete[] FullMsg;
}

void InfoLog(const char* msg, PVOID Address)
{
	char* FullMsg = new char[256];
	if (Address == nullptr)
	{
		sprintf(FullMsg, "%s", msg);
	}
	else
	{
		sprintf(FullMsg, "%s : %p",msg, Address);
	}
	Green;
	LogT("%s\n", FullMsg);
	Gray;
	delete[] FullMsg;
}
