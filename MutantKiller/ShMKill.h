#ifndef _SHMKILL_H_
#define _SHMKILL_H_

#define Log(...) printf("[*] " __VA_ARGS__ )
#define LogT(...) printf("\t[*] " __VA_ARGS__ )
#define ErrLog(...) printf("[!] " __VA_ARGS__ )
#define ErrLogT(...) printf("\t[!] " __VA_ARGS__ )

#define Blue SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_BLUE | FOREGROUND_INTENSITY);
#define Green SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_GREEN | FOREGROUND_INTENSITY);
#define Gray SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
#define Red  SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_RED | FOREGROUND_INTENSITY);
#define Yellow SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY);
#define White SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY);
#define Purple SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_RED | FOREGROUND_BLUE | FOREGROUND_INTENSITY);

void PrintLogo();
void PrintHelp();
void ErrorHandler(const char* msg, ULONG LastError);
void InfoLog(const char* msg, PVOID Address = nullptr);
#endif // !_SHMKILL_H_
