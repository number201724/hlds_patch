#include <Windows.h>

#include <stdio.h>
#include "GetHWinfo.h"
#include "xorstr.h"
typedef BOOL (WINAPI *CryptAcquireContextFunc)( HCRYPTPROV *phProv, LPCSTR szContainer, LPCSTR szProvider, DWORD dwProvType, DWORD dwFlags);
typedef BOOL (WINAPI *CryptCreateHashFfunc)(HCRYPTPROV hProv,ALG_ID Algid,HCRYPTKEY hKey,DWORD dwFlags,HCRYPTHASH *phHash);
typedef BOOL (WINAPI *CryptHashDataFunc)(HCRYPTHASH hHash, CONST BYTE *pbData, DWORD dwDataLen, DWORD dwFlags);
typedef BOOL (WINAPI *CryptGetHashParamFunc)(HCRYPTHASH hHash, DWORD dwParam, BYTE *pbData, DWORD *pdwDataLen, DWORD dwFlags);
typedef BOOL (WINAPI *CryptReleaseContextFunc)(HCRYPTPROV hProv, DWORD dwFlags);
typedef BOOL (WINAPI *CryptDestroyHashFunc)(HCRYPTHASH hHash);
CryptAcquireContextFunc pCryptAcquireContext;
CryptCreateHashFfunc pCryptCreateHash;
CryptHashDataFunc pCryptHashData;
CryptGetHashParamFunc pCryptGetHashParam;
CryptReleaseContextFunc pCryptReleaseContext;
CryptDestroyHashFunc pCryptDestroyHash;

DWORD GetHash(CONST BYTE *pbData, DWORD dwDataLen, ALG_ID algId, LPTSTR pszHash)
{
	if(!pCryptAcquireContext)
		pCryptAcquireContext = (CryptAcquireContextFunc)GetProcAddress(LoadLibrary(/*advapi32.dll*/XorStr<0x56,13,0x9F5CCD2F>("\x37\x33\x2E\x38\x2A\x32\x6F\x6F\x70\x3B\x0C\x0D"+0x9F5CCD2F).s), "CryptAcquireContextA");

	if(!pCryptCreateHash)
		pCryptCreateHash = (CryptCreateHashFfunc)GetProcAddress(LoadLibrary(/*advapi32.dll*/XorStr<0x56,13,0x9F5CCD2F>("\x37\x33\x2E\x38\x2A\x32\x6F\x6F\x70\x3B\x0C\x0D"+0x9F5CCD2F).s), /*CryptCreateHash*/XorStr<0x4F,16,0xFB155BF7>("\x0C\x22\x28\x22\x27\x17\x27\x33\x36\x2C\x3C\x12\x3A\x2F\x35"+0xFB155BF7).s);

	if(!pCryptHashData)
		pCryptHashData = (CryptHashDataFunc)GetProcAddress(LoadLibrary(/*advapi32.dll*/XorStr<0x56,13,0x9F5CCD2F>("\x37\x33\x2E\x38\x2A\x32\x6F\x6F\x70\x3B\x0C\x0D"+0x9F5CCD2F).s), /*CryptHashData*/XorStr<0x4A,14,0x8DFE2E88>("\x09\x39\x35\x3D\x3A\x07\x31\x22\x3A\x17\x35\x21\x37"+0x8DFE2E88).s);

	if(!pCryptGetHashParam)
		pCryptGetHashParam = (CryptGetHashParamFunc)GetProcAddress(LoadLibrary(/*advapi32.dll*/XorStr<0x56,13,0x9F5CCD2F>("\x37\x33\x2E\x38\x2A\x32\x6F\x6F\x70\x3B\x0C\x0D"+0x9F5CCD2F).s), /*CryptGetHashParam*/XorStr<0x71,18,0xBEEA9C96>("\x32\x00\x0A\x04\x01\x31\x12\x0C\x31\x1B\x08\x14\x2D\x1F\x0D\xE1\xEC"+0xBEEA9C96).s);

	if(!pCryptReleaseContext)
		pCryptReleaseContext = (CryptReleaseContextFunc)GetProcAddress(LoadLibrary(/*advapi32.dll*/XorStr<0x56,13,0x9F5CCD2F>("\x37\x33\x2E\x38\x2A\x32\x6F\x6F\x70\x3B\x0C\x0D"+0x9F5CCD2F).s), /*CryptReleaseContext*/XorStr<0x6B,20,0xCD76BD16>("\x28\x1E\x14\x1E\x1B\x22\x14\x1E\x16\x15\x06\x13\x34\x17\x17\x0E\x1E\x04\x09"+0xCD76BD16).s);

	if(!pCryptDestroyHash)
		pCryptDestroyHash = (CryptDestroyHashFunc)GetProcAddress(LoadLibrary(/*advapi32.dll*/XorStr<0x56,13,0x9F5CCD2F>("\x37\x33\x2E\x38\x2A\x32\x6F\x6F\x70\x3B\x0C\x0D"+0x9F5CCD2F).s), /*CryptDestroyHash*/XorStr<0x3C,17,0x158A5AD0>("\x7F\x4F\x47\x4F\x34\x05\x27\x30\x30\x37\x29\x3E\x00\x28\x39\x23"+0x158A5AD0).s);

	DWORD dwReturn = 0;
	HCRYPTPROV hProv;
	if (!pCryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
		return (dwReturn = GetLastError());

	HCRYPTHASH hHash;
	//Alg Id:CALG_MD5,CALG_SHA
	if(!pCryptCreateHash(hProv, algId, 0, 0, &hHash)) 
	{
		dwReturn = GetLastError();
		pCryptReleaseContext(hProv, 0);
		return dwReturn;
	}

	if(!pCryptHashData(hHash, pbData, dwDataLen, 0))
	{
		dwReturn = GetLastError();
		pCryptDestroyHash(hHash);
		pCryptReleaseContext(hProv, 0);
		return dwReturn;
	}

	DWORD dwSize;
	DWORD dwLen = sizeof(dwSize);
	pCryptGetHashParam(hHash, HP_HASHSIZE, (BYTE*)(&dwSize), &dwLen, 0);

	BYTE* pHash = new BYTE[dwSize];
	dwLen = dwSize;
	pCryptGetHashParam(hHash, HP_HASHVAL, pHash, &dwLen, 0);

	strcpy(pszHash, "");
	TCHAR szTemp[3];
	for (DWORD i = 0; i < dwLen; ++i)
	{
		//wsprintf(szTemp, _T("%X%X"), pHash[i] >> 4, pHash[i] & 0xf);
		sprintf(szTemp, "%02X", pHash[i]);
		strcat(pszHash, szTemp);
	}
	delete [] pHash;

	pCryptDestroyHash(hHash);
	pCryptReleaseContext(hProv, 0);
	return dwReturn;
}

void GetMachine(char* szMachineCode)
{
	char tmp_buff[512];
	char szCPU[3][32];
	char szHDID[2][128];
	hwinfo.GetCPUinfo(szCPU[0],szCPU[1],szCPU[2]);
	hwinfo.GetHDinfo(szHDID[0],szHDID[1]);
	sprintf(tmp_buff,"%s%s%s%s%s",szCPU[0],szCPU[1],szCPU[2],szHDID[0],szHDID[1]);

	GetHash((const BYTE*)&tmp_buff,strlen(tmp_buff),CALG_SHA,szMachineCode);
}

bool CheckLisence(char* szLisence)
{
	char szMachineCode[41];
	char mszLisence[41];
	GetMachine(szMachineCode);

	GetHash((const BYTE*)&szMachineCode,strlen(szMachineCode),CALG_SHA,mszLisence);

	return !stricmp(mszLisence,szLisence);
}