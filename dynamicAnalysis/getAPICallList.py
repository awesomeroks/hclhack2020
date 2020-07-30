import json
import glob
def encode(string):
  sum = 0
  for i in range(len(string)):
    sum += ord(string[i])*i
  return sum
path = 'Dynamic_Analysis_Data_Part2/Benign'  + '/*'
total = 0
currFile = ''
callsList = {'GlobalMemoryStatusEx', 'OleInitialize', 'GetDiskFreeSpaceW', 'OutputDebugStringA', 'InternetConnectW', 'RegEnumKeyExA', 'CryptDecrypt', 'NtCreateUserProcess', 'CryptEncrypt', 'WSASendTo', 'NtLoadDriver', 'RtlAddVectoredContinueHandler', 'NetUserGetLocalGroups', 'InternetGetConnectedStateExW', 'NtQueryAttributesFile', 'StartServiceW', 'NtCreateThreadEx', 'NtSetValueKey', 'SHGetFolderPathW', 'OpenSCManagerW', 'DeleteUrlCacheEntryA', 'NtDuplicateObject', 'WriteConsoleW', 'CertCreateCertificateContext', 'CoUninitialize', 'NtCreateSection', 'NetUserGetInfo', 'WSAConnect', 'GetDiskFreeSpaceExW', 'CryptUnprotectData', 'CryptGenKey', 'recvfrom', 'NtLoadKey', 'HttpSendRequestA', 'InternetConnectA', 'GetKeyboardState', 'LoadStringW', 'select', 'NtQueryInformationFile', 'GetFileInformationByHandle', 'CreateServiceA', 'NtOpenThread', 'Thread32Next', 'NtQueryDirectoryFile', 'getaddrinfo', 'socket', 'PRF', 'RemoveDirectoryW', 'SendNotifyMessageW', 'NtReadVirtualMemory', 'GetFileAttributesExW', 'accept', 'CryptDecodeObjectEx', 'CoGetClassObject', 'send', 'GetKeyState', 'WSASend', 'NtQueryKey', 'HttpQueryInfoA', 'FindWindowA', 'CreateRemoteThreadEx', 'NtOpenProcess', 'IWbemServices_ExecQuery', 'CryptAcquireContextA', 'NtUnloadDriver', 'Thread32First', 'SetFileTime', 'HttpSendRequestW', 'MessageBoxTimeoutA', 'RegCloseKey', 'DeviceIoControl', 'Module32NextW', 'NtQuerySystemInformation', 'CreateDirectoryW', 'GetSystemDirectoryA', 'RegCreateKeyExA', 'CryptAcquireContextW', 'CreateJobObjectW', 'InternetOpenUrlA', 'GetTempPathW', 'InternetGetConnectedStateExA', 'LdrLoadDll', 'InternetOpenUrlW', 'NetShareEnum', 'SetWindowsHookExW', 'CertOpenStore', 'SetFileAttributesW', 'SearchPathW', 'SetErrorMode', 'gethostbyname', 'CertControlStore', 'NtFreeVirtualMemory', 'NtCreateKey', 'IsDebuggerPresent', 'OpenServiceW', 'RegisterHotKey', 'RegQueryValueExW', 'CreateRemoteThread', 'CopyFileA', 'InternetCrackUrlW', 'NtWriteVirtualMemory', '__exception__', 'Process32FirstW', 'setsockopt', 'RegDeleteValueA', 'ExitWindowsEx', 'InternetOpenA', 'WNetGetProviderNameW', 'NtProtectVirtualMemory', 'RtlAddVectoredExceptionHandler', 'HttpOpenRequestA', 'ReadProcessMemory', 'CoInitializeSecurity', 'NtDeleteFile', 'DnsQuery_W', 'RegCreateKeyExW', 'InternetCloseHandle', 'CryptUnprotectMemory', 'NtDeleteValueKey', 'UuidCreate', 'SetEndOfFile', 'NtCreateDirectoryObject', 'GetSystemInfo', 'CoCreateInstanceEx', 'OpenServiceA', 'TaskDialog', 'listen', 'RegDeleteKeyW', 'NtMapViewOfSection', 'LookupAccountSidW', 'GetComputerNameA', 'LdrUnloadDll', 'recv', 'NtGetContextThread', 'DrawTextExA', 'RegSetValueExA', 'closesocket', 'NtDeleteKey', 'GetUserNameExW', 'GetUserNameW', 'GetFileAttributesW', 'UnhookWindowsHookEx', 'NtClose', 'GetAdaptersAddresses', 'RtlRemoveVectoredExceptionHandler', 'GetVolumePathNamesForVolumeNameW', 'NtSetContextThread', 'RegQueryInfoKeyW', 'GetForegroundWindow', 'CryptHashData', 'ioctlsocket', '_anomaly', 'CreateServiceW', 'NtSetInformationFile', 'WSASocketW', 'NtSaveKeyEx', 'InternetSetOptionA', 'RegOpenKeyExA', 'NtEnumerateValueKey', 'GlobalMemoryStatus', 'GetNativeSystemInfo', 'CreateActCtxW', 'GetFileType', 'SetFilePointerEx', 'NtReadFile', 'NtQueryValueKey', 'CertOpenSystemStoreW', 'GetAdaptersInfo', 'EnumServicesStatusA', 'CryptCreateHash', 'DnsQuery_A', 'GetSystemDirectoryW', 'NtTerminateThread', 'NtResumeThread', 'RegQueryInfoKeyA', 'NtSuspendThread', 'GetFileInformationByHandleEx', 'NtDelayExecution', 'NtOpenMutant', 'InternetWriteFile', 'NtWriteFile', 'NtOpenSection', 'GetVolumeNameForVolumeMountPointW', 'IWbemServices_ExecMethod', 'NtQueryMultipleValueKey', 'LookupPrivilegeValueW', 'NtOpenKeyEx', 'GetSystemWindowsDirectoryA', 'SetStdHandle', 'NtOpenKey', 'HttpOpenRequestW', 'InternetOpenW', 'NtQueryFullAttributesFile', 'FindResourceW', 'SetUnhandledExceptionFilter', 'NtEnumerateKey', 'AssignProcessToJobObject', 'MessageBoxTimeoutW', 'NtCreateFile', 'WSASocketA', 'connect', 'NetGetJoinInformation', 'bind', 'NtCreateMutant', 'CopyFileExW', 'CopyFileW', 'NtQueueApcThread', 'InternetQueryOptionA', 'GetInterfaceInfo', 'DeleteUrlCacheEntryW', 'StartServiceA', 'RegEnumKeyExW', 'NtOpenDirectoryObject', 'LoadResource', 'URLDownloadToFileW', 'SHGetSpecialFolderLocation', 'GetSystemTimeAsFileTime', 'CryptProtectMemory', 'GetSystemMetrics', 'OpenSCManagerA', 'InternetReadFile', 'GetFileSizeEx', 'FindResourceExW', 'GetVolumePathNameW', 'GetBestInterfaceEx', 'SetInformationJobObject', 'NtUnmapViewOfSection', 'NtAllocateVirtualMemory', 'FindWindowExW', 'RegEnumValueW', 'ReadCabinetState', 'RtlCreateUserThread', 'DeleteFileW', 'LdrGetProcedureAddress', 'RegOpenKeyExW', 'GetShortPathNameW', 'CryptProtectData', 'SetFilePointer', 'NtOpenFile', 'SizeofResource', 'RegDeleteKeyA', 'LoadStringA', 'DeleteService', 'DecryptMessage', 'GetFileVersionInfoSizeW', 'EnumServicesStatusW', 'RtlCompressBuffer', 'GetFileSize', 'getsockname', 'NtDeviceIoControlFile', 'MoveFileWithProgressW', 'WriteConsoleA', 'NtShutdownSystem', 'RegDeleteValueW', 'CreateThread', 'FindFirstFileExA', 'GetFileVersionInfoExW', 'InternetGetConnectedState', 'InternetCrackUrlA', 'RtlDecompressBuffer', 'GetCursorPos', 'GetAsyncKeyState', 'FindWindowExA', 'SendNotifyMessageA', 'FindWindowW', 'EnumWindows', 'GetSystemWindowsDirectoryW', 'NtTerminateProcess', 'CertOpenSystemStoreA', 'SetFileInformationByHandle', 'DrawTextExW', 'WriteProcessMemory', 'RegEnumValueA', 'ShellExecuteExW', 'GetAddrInfoW', 'timeGetTime', 'FindResourceA', 'WSARecv', 'InternetSetStatusCallback', 'exception_', 'CoInitializeEx', 'GetComputerNameW', 'CryptExportKey', 'SetWindowsHookExA', 'sendto', 'RegQueryValueExA', 'LdrGetDllHandle', 'RegEnumKeyW', 'ControlService', 'GetUserNameA', 'Process32NextW', 'FindFirstFileExW', 'FindResourceExA', 'shutdown', 'RemoveDirectoryA', 'RegSetValueExW', 'CoCreateInstance', 'ObtainUserAgentString', 'CryptHashMessage', 'WSAStartup', 'WSARecvFrom', 'WSAAccept', 'GetUserNameExA', 'EncryptMessage', 'CreateToolhelp32Snapshot', 'CreateDirectoryExW', 'CreateProcessInternalW', 'system', 'Module32FirstW', 'GetFileVersionInfoSizeExW', 'GetFileVersionInfoW', 'GetTimeZoneInformation'}
for filepath in glob.iglob(path):
  total += 1
  if total < 700:
    continue
  file = open(filepath,'r')
  jsonData = json.loads(file.read())
  callCountTemp = jsonData['behavior']['apistats']
  for item in callCountTemp:
      for key in callCountTemp[item]:
          callsList.add(key)
  file.close()
  
  
  if total%100 == 0:
    opFile = open('op.txt','w')
    opFile.write(str(callsList))
    opFile.close()
  elif total%25 == 0:
    print(total, len(callsList))
  currFile = filepath
  if len(callsList) >=534:
    break
opFile = open('op.txt','w')
opFile.write(str(callsList))
opFile.close()
print(total)
print(currFile)
print(len(callsList))

