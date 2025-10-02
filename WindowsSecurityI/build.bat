@ECHO OFF

REM
REM _MBCS -> use multi-byte charsets, WIN32->32 bit platform, _WINDOWS -> Windows build
REM
SET DEFINES=/D _MBCS /D WIN32 /D _WINDOWS

REM
REM Adapt library path to wherever the libraries reside
REM
SET LIBPATH=/LIBPATH:"C:\Program Files (x86)\Windows Kits\10\Lib\10.0.26100.0\um\x86"
SET LIBRARIES=kernel32.Lib USER32.LIB GDI32.LIB WINSPOOL.LIB SHELL32.LIB OLE32.LIB OLEAUT32.LIB UUID.LIB COMDLG32.LIB ADVAPI32.LIB

REM
REM 0d-> no optimization and debugging info, EHsc add exception support
REM Zc:wchar_t->use wchar_t as builtin type, Gd -> cdecl calling convention, GR -> enable RTTI
REM
SET CCOPTS=/Od /EHsc /MTd /Zc:wchar_t /Gd /GR

cl /LD /nologo %DEFINES% /D _WINDLL %CCOPTS% src/mylib.cpp     /link %LIBPATH% %LIBRARIES% /out:mylib.dll
cl     /nologo %DEFINES%            %CCOPTS% src/mylibtest.cpp /link %LIBPATH% %LIBRARIES% /out:mylibtest.exe
