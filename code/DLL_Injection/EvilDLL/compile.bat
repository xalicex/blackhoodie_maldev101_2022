ECHO OFF
cl.exe /nologo /Od /MT /W1 /D_USRDLL /D_WINDLL /DNDEBUG  /D "_UNICODE" /D "UNICODE"  /TC *.c /link /DLL /OUT:EvilDLL.dll /SUBSYSTEM:CONSOLE /MACHINE:x64
del *.obj