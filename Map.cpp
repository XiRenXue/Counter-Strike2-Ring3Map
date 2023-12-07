#include <Windows.h>


BOOL Map(DWORD ProcessId, CONST CHAR* DllPath) {
    if (!ProcessId) return FALSE;
    if (!DllPath) return FALSE;
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, ProcessId);
    if (!hProcess) return FALSE;
    HMODULE Ntdll = GetModuleHandleA("ntdll.dll");
    if (!Ntdll) {
		CloseHandle(hProcess);
		return FALSE;
	}
    FARPROC NtOpenFile = GetProcAddress(Ntdll, "NtOpenFile");
    if (!NtOpenFile) {
        CloseHandle(hProcess);
        return FALSE;
    }
    BYTE NtOpenFileHook[5] = { 0 };
    if (!ReadProcessMemory(hProcess, (LPCVOID)NtOpenFile, NtOpenFileHook, 5, NULL)) {
		CloseHandle(hProcess);
		return FALSE;
    }
    if (NtOpenFileHook[0] == 233) {
        BYTE MyNtOpenFile[5] = { 0 };
        RtlCopyMemory(MyNtOpenFile, NtOpenFile, 5);
        DWORD Protection = 0;
        if (!VirtualProtectEx(hProcess, NtOpenFile, 5, PAGE_EXECUTE_READWRITE, &Protection)) {
            CloseHandle(hProcess);
            return FALSE;
        }
        if (!WriteProcessMemory(hProcess, NtOpenFile, MyNtOpenFile, 5, NULL)) {
			CloseHandle(hProcess);
			return FALSE;
		}
        if (!VirtualProtectEx(hProcess, NtOpenFile, 5, Protection, &Protection)) {
            CloseHandle(hProcess);
            return FALSE;
        }
    }
	LPVOID NewAddress = VirtualAllocEx(hProcess, 0, sizeof(DllPath) + 1, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (!NewAddress) {
		CloseHandle(hProcess);
		return FALSE;
	}
	if (!WriteProcessMemory(hProcess, NewAddress, DllPath, sizeof(DllPath), NULL)) {
        VirtualFreeEx(hProcess, NewAddress, 0, MEM_RELEASE);
		CloseHandle(hProcess);
		return FALSE;
	}
	HANDLE hThread = CreateRemoteThread(hProcess, 0, 0, (LPTHREAD_START_ROUTINE)LoadLibraryA, NewAddress, 0, 0);
	if (!hThread) {
        VirtualFreeEx(hProcess, NewAddress, 0, MEM_RELEASE);
		CloseHandle(hProcess);
		return FALSE;
	}
	WaitForSingleObject(hThread, INFINITE);
	CloseHandle(hThread);
	VirtualFreeEx(hProcess, NewAddress, 0, MEM_RELEASE);
	CloseHandle(hProcess);
	return TRUE;
}
