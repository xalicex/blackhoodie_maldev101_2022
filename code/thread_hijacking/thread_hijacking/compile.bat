ECHO OFF
cl.exe /nologo /Od /MT /W1 /DNDEBUG  /D "_UNICODE" /D "UNICODE"  /TC *.c /link /OUT:thread_hijacking.exe /SUBSYSTEM:CONSOLE /MACHINE:x64
del *.obj