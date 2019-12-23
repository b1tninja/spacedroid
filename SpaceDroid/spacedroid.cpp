#include <stdio.h>
#include <wchar.h>
#include <windows.h>
#include <tlhelp32.h>  
#include <shlwapi.h>  
#include <cstdarg>

//#include <Python.h>
typedef void PyObject;
//#include <pystate.h>
typedef enum { PyGILState_LOCKED, PyGILState_UNLOCKED } PyGILState_STATE;

char* caption = "Space Droid";
HMODULE hModule;
LPWSTR eveExe = L"exefile.exe";
char* pythonDllName = "python27";
//char* pipeName = "\\\\.\\pipe\\spacedroid";
HMODULE pyModule;

#pragma intrinsic(memset)

char buffer[1024] = { };
const int buflen = sizeof(buffer) / sizeof(*buffer);

int Py_IsInitialized() {
	typedef int(__cdecl * procdef)(VOID);
	static FARPROC procaddr;
	static procdef proc;
	if (procaddr == NULL) {
		procaddr = GetProcAddress(pyModule, "Py_IsInitialized");
		proc = (procdef)procaddr;
	}
	if (proc == NULL) {
		MessageBoxA(NULL, "Failed to GetProcAddress for Py_IsInitialized", caption, MB_OK | MB_ICONERROR);
	}
	else {
		return proc();
	}
	return -1;
}

PyObject* PyImport_AddModule(char* module) {
	typedef PyObject*(__cdecl *procdef)(char*);
	static FARPROC procaddr;
	static procdef proc;
	if (procaddr == NULL) {
		procaddr = GetProcAddress(pyModule, "PyImport_AddModule");
		proc = (procdef)procaddr;
	}
	if (proc == NULL) {
		MessageBoxA(NULL, "Failed to GetProcAddress for PyImport_AddModule", caption, MB_OK | MB_ICONERROR);
	}
	else {
		return proc(module);
	}
}


PyObject* PyImport_ImportModule(char* module) {
	typedef PyObject*(__cdecl *procdef)(char*);
	static FARPROC procaddr;
	static procdef proc;
	if (procaddr == NULL) {
		procaddr = GetProcAddress(pyModule, "PyImport_ImportModule");
		proc = (procdef)procaddr;
	}
	if (proc == NULL) {
		MessageBoxA(NULL, "Failed to GetProcAddress for PyImport_ImportModule", caption, MB_OK | MB_ICONERROR);
	}
	else {
		return proc(module);
	}
}


//PyObject* PyImport_ImportModuleEx(char* name, PyObject* globals, PyObject* locals, PyObject* fromlist) {
//	typedef PyObject*(__cdecl *procdef)(char*, PyObject*, PyObject*, PyObject*);
//	static FARPROC procaddr;
//	static procdef proc;
//	if (procaddr == NULL) {
//		procaddr = GetProcAddress(pyModule, "PyImport_ImportModuleEx");
//		proc = (procdef)procaddr;
//	}
//	if (proc == NULL) {
//		MessageBox(NULL, TEXT("Failed to GetProcAddress for PyImport_ImportModuleEx"), caption, MB_OK | MB_ICONERROR);
//	}
//	else {
//		return proc(name, globals, locals, fromlist);
//	}
//}

PyObject* PyImport_Import(PyObject* name) {
	typedef PyObject*(__cdecl *procdef)(PyObject*);
	static FARPROC procaddr;
	static procdef proc;
	if (procaddr == NULL) {
		procaddr = GetProcAddress(pyModule, "PyImport_Import");
		proc = (procdef)procaddr;
	}
	if (proc == NULL) {
		MessageBoxA(NULL, "Failed to GetProcAddress for PyImport_Import", caption, MB_OK | MB_ICONERROR);
	}
	else {
		return proc(name);
	}
}


char* Py_GetPath(void) {
	typedef char*(__cdecl *procdef)(void);
	static FARPROC procaddr;
	static procdef proc;
	if (procaddr == NULL) {
		procaddr = GetProcAddress(pyModule, "Py_GetPath");
		proc = (procdef)procaddr;
	}
	if (proc == NULL) {
		MessageBoxA(NULL, "Failed to GetProcAddress for Py_GetPath", caption, MB_OK | MB_ICONERROR);
	}
	else {
		return proc();
	}
}
	

void Py_SetPath(char* path) {
	typedef void(__cdecl *procdef)(char*);
	static FARPROC procaddr;
	static procdef proc;
	if (procaddr == NULL) {
		procaddr = GetProcAddress(pyModule, "Py_SetPath");
		proc = (procdef)procaddr;
	}
	if (proc == NULL) {
		MessageBoxA(NULL, "Failed to GetProcAddress for Py_SetPath", caption, MB_OK | MB_ICONERROR);
	}
	else {
		return proc(path);
	}
}

PyObject* PyModule_GetDict(PyObject* module) {
	typedef PyObject*(__cdecl *procdef)(PyObject*);
	static FARPROC procaddr;
	static procdef proc;
	if (procaddr == NULL) {
		procaddr = GetProcAddress(pyModule, "PyModule_GetDict");
		proc = (procdef)procaddr;
	}
	if (proc == NULL) {
		MessageBoxA(NULL, "Failed to GetProcAddress for PyModule_GetDict", caption, MB_OK | MB_ICONERROR);
	}
	else {
		return proc(module);
	}
}


PyObject* PyDict_GetItemString(PyObject* dict, char* key) {
	typedef PyObject*(__cdecl *procdef)(PyObject*, char*);
	static FARPROC procaddr;
	static procdef proc;
	if (procaddr == NULL) {
		procaddr = GetProcAddress(pyModule, "PyDict_GetItemString");
		proc = (procdef)procaddr;
	}
	if (proc == NULL) {
		MessageBoxA(NULL, "Failed to GetProcAddress for PyDict_GetItemString", caption, MB_OK | MB_ICONERROR);
	}
	else {
		return proc(dict, key);
	}
	return NULL;
}

PyObject* PyObject_GetAttrString(PyObject* dict, char* attr) {
	typedef PyObject*(__cdecl *procdef)(PyObject*, char*);
	static FARPROC procaddr;
	static procdef proc;
	if (procaddr == NULL) {
		procaddr = GetProcAddress(pyModule, "PyObject_GetAttrString");
		proc = (procdef)procaddr;
	}
	if (proc == NULL) {
		MessageBoxA(NULL, "Failed to GetProcAddress for PyObject_GetAttrString", caption, MB_OK | MB_ICONERROR);
	}
	else {
		return proc(dict, attr);
	}
	return NULL;
}

void Py_DecRef(PyObject* object) {
	typedef void(__cdecl *procdef)(PyObject*);
	static FARPROC procaddr;
	static procdef proc;
	if (procaddr == NULL) {
		procaddr = GetProcAddress(pyModule, "Py_DecRef");
		proc = (procdef)procaddr;
	}
	if (proc == NULL) {
		MessageBoxA(NULL, "Failed to GetProcAddress for Py_DecRef", caption, MB_OK | MB_ICONERROR);
	}
	else {
		proc(object);
	}
}

PyObject* PyUnicodeUCS2_FromString(char* str) {
	typedef PyObject*(__cdecl *procdef)(char*);
	static FARPROC procaddr;
	static procdef proc;
	if (procaddr == NULL) {
		procaddr = GetProcAddress(pyModule, "PyUnicodeUCS2_FromString");
		proc = (procdef)procaddr;
	}
	if (proc == NULL) {
		MessageBoxA(NULL, "Failed to GetProcAddress for PyUnicodeUCS2_FromString", caption, MB_OK | MB_ICONERROR);
	}
	else {
		return proc(str);
	}
}


PyObject* PyString_FromString(char* str) {
	typedef PyObject*(__cdecl *procdef)(char*);
	static FARPROC procaddr;
	static procdef proc;
	if (procaddr == NULL) {
		procaddr = GetProcAddress(pyModule, "PyString_FromString");
		proc = (procdef)procaddr;
	}
	if (proc == NULL) {
		MessageBoxA(NULL, "Failed to GetProcAddress for PyString_FromString", caption, MB_OK | MB_ICONERROR);
	}
	else {
		return proc(str);
	}
}

char* PyString_AsString(PyObject* object) {
	typedef char*(__cdecl *procdef)(PyObject*);
	static FARPROC procaddr;
	static procdef proc;
	if (procaddr == NULL) {
		procaddr = GetProcAddress(pyModule, "PyString_AsString");
		proc = (procdef)procaddr;
	}
	if (proc == NULL) {
		MessageBoxA(NULL, "Failed to GetProcAddress for PyString_AsString", caption, MB_OK | MB_ICONERROR);
	}
	else {
		return proc(object);
	}
}

PyObject* Py_BuildValue(char* format, ...) {
	va_list va;
	typedef PyObject*(__cdecl *procdef)(char*, ...);
	static FARPROC procaddr;
	static procdef proc;
	if (procaddr == NULL) {
		procaddr = GetProcAddress(pyModule, "Py_BuildValue");
		proc = (procdef)procaddr;
	}
	if (proc == NULL) {
		MessageBoxA(NULL, "Failed to GetProcAddress for Py_BuildValue", caption, MB_OK | MB_ICONERROR);
	}
	else {
		return proc(format, va);
	}

}

PyObject* PyObject_Repr(PyObject* object) {
	typedef PyObject*(__cdecl *procdef)(PyObject*);
	static FARPROC procaddr;
	static procdef proc;
	if (procaddr == NULL) {
		procaddr = GetProcAddress(pyModule, "PyObject_Repr");
		proc = (procdef)procaddr;
	}
	if (proc == NULL) {
		MessageBoxA(NULL, "Failed to GetProcAddress for PyObject_Repr", caption, MB_OK | MB_ICONERROR);
	}
	else {
		return proc(object);
	}
}

PyObject* PyObject_Str(PyObject* object) {
	typedef PyObject*(__cdecl *procdef)(PyObject*);
	static FARPROC procaddr;
	static procdef proc;
	if (procaddr == NULL) {
		procaddr = GetProcAddress(pyModule, "PyObject_Str");
		proc = (procdef)procaddr;
	}
	if (proc == NULL) {
		MessageBoxA(NULL, "Failed to GetProcAddress for PyObject_Str", caption, MB_OK | MB_ICONERROR);
	}
	else {
		return proc(object);
	}
}

PyObject* PyObject_Dir(PyObject* object) {
	typedef PyObject*(__cdecl *procdef)(PyObject*);
	static FARPROC procaddr;
	static procdef proc;
	if (procaddr == NULL) {
		procaddr = GetProcAddress(pyModule, "PyObject_Dir");
		proc = (procdef)procaddr;
	}
	if (proc == NULL) {
		MessageBoxA(NULL, "Failed to GetProcAddress for PyObject_Dir", caption, MB_OK | MB_ICONERROR);
	}
	else {
		return proc(object);
	}
}


PyObject* PyObject_CallMethod(PyObject* object, char* method, char* format, ...) {
	va_list va;
	typedef PyObject*(__cdecl *procdef)(PyObject*, char*, char*, ...);
	static FARPROC procaddr;
	static procdef proc;
	if (procaddr == NULL) {
		procaddr = GetProcAddress(pyModule, "PyObject_CallMethod");
		proc = (procdef)procaddr;
	}
	if (proc == NULL) {
		MessageBoxA(NULL, "Failed to GetProcAddress for PyObject_CallMethod", caption, MB_OK | MB_ICONERROR);
	}
	else {
		return proc(object, method, format, va);
	}
}

PyGILState_STATE PyGILState_Ensure() {
	typedef PyGILState_STATE(__cdecl *procdef)(void);
	static FARPROC procaddr;
	static procdef proc;
	if (procaddr == NULL) {
		procaddr = GetProcAddress(pyModule, "PyGILState_Ensure");
		proc = (procdef)procaddr;
	}
	if (proc == NULL) {
		MessageBoxA(NULL, "Failed to GetProcAddress for PyGILState_Ensure", caption, MB_OK | MB_ICONERROR);
	}
	else {
		return proc();
	}
	//return PyGILState_UNLOCKED;
}


void PyGILState_Release(PyGILState_STATE state) {
	typedef void(__cdecl *procdef)(PyGILState_STATE);
	static FARPROC procaddr;
	static procdef proc;
	if (procaddr == NULL) {
		procaddr = GetProcAddress(pyModule, "PyGILState_Release");
		proc = (procdef)procaddr;
	}
	if (proc == NULL) {
		MessageBoxA(NULL, "Failed to GetProcAddress for PyGILState_Release", caption, MB_OK | MB_ICONERROR);
	}
	else {
		proc(state);
	}
}

int PyRun_SimpleString(char* code) {
	typedef int(__cdecl *procdef)(char*);
	static FARPROC procaddr;
	static procdef proc;
	if (procaddr == NULL) {
		procaddr = GetProcAddress(pyModule, "PyRun_SimpleString");
		proc = (procdef)procaddr;
	}
	if (proc == NULL) {
		MessageBoxA(NULL, "Failed to GetProcAddress for PyRun_SimpleString", caption, MB_OK | MB_ICONERROR);
	}
	else {
		return proc(code);
	}
}



char* repr(PyObject* object) {
	if (object != NULL) {
		PyObject* objrepr = PyObject_Repr(object);
		if (objrepr != NULL) {
			return PyString_AsString(objrepr);
		}
	}
	return NULL;
}

char* str(PyObject* object) {
	if (object != NULL) {
		PyObject* pyobjstr = PyObject_Str(object);
		if (pyobjstr != NULL) {
			return PyString_AsString(pyobjstr);
		}
	}
	return NULL;
}


PyObject* getGlobal(char* name) {
	PyObject* __builtin__ = PyImport_AddModule("__builtin__");
	if (__builtin__ == NULL)
	{
		MessageBoxA(NULL, "PyImport_AddModule(__builtin__) returned null.", caption, MB_OK);
	}
	else {

		PyObject* dict = PyModule_GetDict(__builtin__);

		if (dict == NULL)
		{
			MessageBoxA(NULL, "PyModule_GetDict(__builtin__) returned null.", caption, MB_OK);
		}
		else {
			PyObject* global = PyDict_GetItemString(dict, name);
			if (global == NULL)
			{
				wsprintfA(buffer, "PyDict_GetItemString(__builtin__, '%s') returned null.", name);
				MessageBoxA(NULL, buffer, caption, MB_OK);
			}
			else {
				return global;
			}
		}
	}
	return NULL;

}


PyObject* getService(char* name)
{
	PyObject* serviceManager = getGlobal("sm");
	repr(serviceManager);
	if (serviceManager != NULL)
	{
		PyObject* service = PyObject_CallMethod(serviceManager, "GetService", "(s)", name);
		if (service == NULL)
		{
			MessageBoxA(NULL, "PyObject_CallMethod(sm, 'GetService', '(s)', ...) returned null.", caption, MB_OK);
		}
		else {
			return service;
		}

	}
	return NULL;
}


void Say(char* message) {
	//*/ sm.GetService("gameui").Say(u"Hello world")
	PyObject* gameui_service = getService("gameui");
	if (gameui_service) {
		//repr(gameui_service);
		PyObject* umsg = PyUnicodeUCS2_FromString(message);
		PyObject_CallMethod(gameui_service, "Say", "(S)", umsg);
	}
#ifdef _DEBUG
	else {
		MessageBoxA(NULL, "Failed attempting to get gameui service.", caption, MB_OK | MB_ICONERROR);
	}
#endif
}


PyObject* GetBallpark() {
	PyObject* michelle_service = getService("michelle");
	if (michelle_service) {
		return PyObject_CallMethod(michelle_service, "GetBallpark", "()", NULL);
	}

	return NULL;
}


void _eval(char* code) {
	static HMODULE pyModule = GetModuleHandleA(pythonDllName);;
	if (pyModule == NULL) {
		wsprintfA(buffer, "Unable to GetModuleHandle: %s", pythonDllName);
		MessageBoxA(NULL, buffer, caption, MB_OK | MB_ICONERROR);
	}
	else {
		if (Py_IsInitialized()) {
			PyGILState_STATE gstate = PyGILState_Ensure();
			PyRun_SimpleString(code);
			PyGILState_Release(gstate);
		}
		else {
#ifdef _DEBUG
			MessageBoxA(NULL, "Python is not initialized.", caption, MB_OK);
#endif
		}
	}
	FreeLibraryAndExitThread(hModule, 0);
}


LPVOID remote_memcpy(HANDLE hProcess, LPVOID source, SIZE_T size) {

	LPVOID alloc = (LPVOID)VirtualAllocEx(hProcess, NULL, size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (alloc) {
#ifdef  _DEBUG
		wsprintfA(buffer, "Memory allocated, writting %d bytes, to 0x%x...", size, &alloc);
		MessageBoxA(NULL, buffer, caption, NULL);
#endif
		if (WriteProcessMemory(hProcess, (LPVOID)alloc, source, size, NULL)) {
			return alloc;
		}
	}
	return NULL;
}


BOOL WINAPI DllMain(HMODULE _hModule, DWORD  ul_reason_for_call, LPVOID lpReserved)
{
	static int n = 0;
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		hModule = _hModule;

		//if (!_wcsicmp(procPath + max(0, wcslen(procPath) - wcslen(eveExe)), eveExe)) {}
		pyModule = GetModuleHandleA(pythonDllName);
		if (pyModule != NULL) {
			if (!Py_IsInitialized()) {
				MessageBoxA(NULL, "Python is loaded but not initialized", caption, MB_OK | MB_ICONERROR);
				return FALSE;
			}
			//else {

			//	Say("I'm in your process, calling your methods.");
			//	Say(repr(GetBallpark()));
			//	PyRun_SimpleString("import pprint\nsdfh = open(r'c:\\tmp\\pretty.txt','wt')\nsdpp = pprint.PrettyPrinter(stream=sdfh)\nsdpp.pprint(sm.GetService('michelle').GetBallpark().__dict__)");

			//	/*
			//	PyObject* module = PyImport_Import(PyString_FromString("space_droid"));
			//	#ifdef _DEBUG
			//	if (module) {
			//	swprintf(buffer, buflen, TEXT("PyImport_Import returned: 0x%x, VICTORY"), module);
			//	MessageBox(NULL, buffer, caption, MB_OK | MB_ICONASTERISK);
			//	}
			//	else {
			//	MessageBox(NULL, TEXT("PyImport_ImportModule failed"), caption, MB_OK | MB_ICONERROR);
			//	}
			//	#endif
			//	*/
			//}
			
		}

		DisableThreadLibraryCalls(hModule);
		break;
	case DLL_THREAD_ATTACH:

	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
	default:
		break;
	}
	return TRUE;
}


HANDLE _inject(DWORD pid, LPVOID proc, LPVOID param, SIZE_T param_size) {
	static LPVOID LoadLibAddress;
	static char dllPath[MAX_PATH] = { };

	LPVOID dllPath_copy;

	HANDLE hLoadLibThread;
	DWORD base;
	HANDLE hThread;

	LPVOID rebased_proc;
	LPVOID param_copy = NULL;

	if (LoadLibAddress == NULL) {
		LoadLibAddress = (LPVOID)GetProcAddress(GetModuleHandleA("kernel32"), "LoadLibraryA");
		GetModuleFileNameA(hModule, dllPath, sizeof(dllPath));
	}

	HANDLE hProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, FALSE, pid);
	if (hProcess) {


		dllPath_copy = remote_memcpy(hProcess, dllPath, (SIZE_T)(lstrlenA(dllPath) + 1) * sizeof(*dllPath));

		if (dllPath_copy != NULL) {
			hLoadLibThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)LoadLibAddress, (LPVOID)dllPath_copy, 0, NULL);
			if (hLoadLibThread != NULL) {
				// Wait for thread to finish, to get the returned base address
				WaitForSingleObject(hLoadLibThread, INFINITE);
				GetExitCodeThread(hLoadLibThread, &base);
				CloseHandle(hLoadLibThread);

				if (base != NULL) {
					// Ultimately, we don't need the base address because ASLR not in use, but lets calculate it anyway.
					rebased_proc = (LPVOID)((DWORD)proc - (DWORD)hModule + base);
#ifdef _DEBUG
					wsprintfA(buffer, "LoadLibrary returned: 0x%x, + &proc (0x%0x)- hModule (0x%0x) = 0x%0x", base, proc, (DWORD)hModule, (DWORD)rebased_proc);
					MessageBoxA(NULL, buffer, caption, NULL);

#endif
					if (param != NULL)
						param_copy = remote_memcpy(hProcess, param, param_size);

					hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)rebased_proc, param_copy, 0, NULL);
					if (hThread != NULL) {
						return hThread;
					}
#ifdef _DEBUG
					else {
						wsprintfA(buffer, "Unable to CreateRemoteThread, GetLastError: %d", GetLastError());
						MessageBoxA(NULL, buffer, caption, MB_ICONERROR);
					}
#endif

				}
#ifdef _DEBUG
				else {

					wsprintfA(buffer, "LoadLibrary (0x%0x) returned 0x%0x, last error: %d", hLoadLibThread, base, GetLastError());
					MessageBoxA(NULL, buffer, caption, MB_ICONERROR);
				}
#endif
			}
			VirtualFreeEx(hProcess, dllPath_copy, 0, MEM_RELEASE);
		}
		CloseHandle(hProcess);
	}
	return 0;
}


extern "C" __declspec(dllexport) BOOL eval(HWND hwnd, HINSTANCE hinst, LPSTR lpszCmdLine, int nCmdShow)
{
	if (lstrlenA(lpszCmdLine) == 0) {
		lpszCmdLine = "import code\ncode.interact()";
	}
	BOOL success = FALSE;
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnapshot != INVALID_HANDLE_VALUE)
	{
		PROCESSENTRY32 pe; // = {}; // WHY IS THIS TURNED INTO MEMSET?!
		//ZeroMemory(&pe, sizeof(pe)); // IS THERE NO GOD? F_CkIt();
		pe.dwSize = sizeof(PROCESSENTRY32);
		BOOL bRet = Process32First(hSnapshot, &pe);
		while (bRet)
		{
			if (!lstrcmpiW(pe.szExeFile, eveExe))
			{
#ifdef  _DEBUG
				wsprintfA(buffer, "Found, %S (%d)...", pe.szExeFile, pe.th32ProcessID);
				MessageBoxA(NULL, buffer, caption, MB_OK);
#endif
				//char code[] = "sm.GetService('gameui').Say(u'Hello World')";
				//HANDLE hThread = _inject(pe.th32ProcessID, &_eval, code, sizeof(code));
				HANDLE hThread = _inject(pe.th32ProcessID, &_eval, lpszCmdLine, lstrlenA(lpszCmdLine));
				if (hThread) {
#ifdef _DEBUG
					wsprintfA(buffer, "Injected, thread handle: 0x%x", hThread);
					MessageBoxA(hwnd, buffer, caption, MB_OK);
#endif
					WaitForSingleObject(hThread, INFINITE);
					CloseHandle(hThread);

					success = TRUE;
				}

				//break;
			}
			bRet = Process32Next(hSnapshot, &pe);
		}
		CloseHandle(hSnapshot);
	}
	return success;
}