Like rundll32 but for a remote process. Injects a DLL into a process and runs a function within it.

Usage:
injectdll.exe exe dll function params

Example:
injectdll.exe notepad.exe sampledll.dll MyMessageBox "hello world"