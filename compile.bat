ECHO OFF
cl.exe /nologo /Od /MT /W1 /DNDEBUG  /D "_UNICODE" /D "UNICODE"  /TC *.c /link /OUT:injection.exe /SUBSYSTEM:CONSOLE /MACHINE:x64
del *.obj
