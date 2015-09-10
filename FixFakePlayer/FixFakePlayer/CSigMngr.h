/**
 * (C)2003-2006 David "BAILOPAN" Anderson
 * Counter-Strike: Deathmatch
 *
 * Licensed under the GNU General Public License, version 2
 */

#ifndef _INCLUDE_CSIGMNGR_H
#define _INCLUDE_CSIGMNGR_H

struct signature_t
{
	void *allocBase;
	void *memInBase;
	size_t memSize;
	void *offset;
	const char *sig;
	size_t siglen;
};

class CSigMngr
{
public:
	void *ResolveSig(void *memInBase, const char *pattern, size_t siglen);
	int ResolvePattern(void *memInBase, const char *pattern, size_t siglen, int number, ...);
private:
	bool ResolveAddress(signature_t *sigmem);
};

extern CSigMngr g_SigMngr;


#define FIND_MEMORY(address, sig) (g_SigMngr.ResolveSig((void *)address, sig, sig##_BYTES)); 


inline BOOL mprotect(void *addr, int length, int prot)
{
	DWORD old_prot;
	return VirtualProtect(addr, length, prot, &old_prot);
}

inline void pmemcpy(void* pBase, void* pCode ,size_t dwSize)
{
	DWORD dwOldFlag = 0;
	DWORD dwOldFlag2;
	VirtualProtect(pBase, dwSize, PAGE_EXECUTE_READWRITE, &dwOldFlag); // Modify DesFunc Memory Access
	memcpy(pBase, pCode, dwSize);
	VirtualProtect(pBase, dwSize, dwOldFlag, &dwOldFlag2); // Fix DesFunc Memory Access
}

#endif //_INCLUDE_CSIGMNGR_H
