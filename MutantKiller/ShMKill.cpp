#include "ShInc.h"


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
