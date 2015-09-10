#include <Windows.h>
#include "CSigMngr.h"

CSigMngr g_SigMngr;


bool CSigMngr::ResolveAddress(signature_t *sigmem)
{
	MEMORY_BASIC_INFORMATION mem;

	if (!VirtualQuery(sigmem->memInBase, &mem, sizeof(MEMORY_BASIC_INFORMATION)))
		return false;

	if (mem.AllocationBase == NULL)
		return false;

	HMODULE dll = (HMODULE)mem.AllocationBase;

	//code adapted from hullu's linkent patch
	union 
	{
		unsigned long mem;
		IMAGE_DOS_HEADER *dos;
		IMAGE_NT_HEADERS *pe;
	} dllmem;

	dllmem.mem = (unsigned long)dll;

	if (IsBadReadPtr(dllmem.dos, sizeof(IMAGE_DOS_HEADER)) || (dllmem.dos->e_magic != IMAGE_DOS_SIGNATURE))
		return false;

	dllmem.mem = ((unsigned long)dll + (unsigned long)(dllmem.dos->e_lfanew));
	if (IsBadReadPtr(dllmem.pe, sizeof(IMAGE_NT_HEADERS)) || (dllmem.pe->Signature != IMAGE_NT_SIGNATURE))
		return false;

	//end adapted hullu's code

	IMAGE_NT_HEADERS *pe = dllmem.pe;

	sigmem->allocBase = mem.AllocationBase;
	sigmem->memSize = (DWORD)(pe->OptionalHeader.SizeOfImage);

	return true;
}

void *CSigMngr::ResolveSig(void *memInBase, const char *pattern, size_t siglen)
{
	signature_t sig;

	memset(&sig, 0, sizeof(signature_t));

	sig.sig = (const char *)pattern;
	sig.siglen = siglen;
	sig.memInBase = memInBase;

	if (!ResolveAddress(&sig))
		return NULL;

	const char *paddr = (const char *)sig.allocBase;
	bool found;

	register unsigned int j;

	sig.memSize -= sig.siglen;	//prevent a crash maybe?

	for (size_t i=0; i<sig.memSize; i++)
	//for (size_t i=0; i<sig.memSize; i+=sizeof(unsigned long *))
	{
		found = true;
		for (j=0; j<sig.siglen; j++)
		{
			if ( (pattern[j] != (unsigned char)0x2A) &&
				 (pattern[j] != paddr[j]) )
			{
				found = false;
				break;
			}
		}
		if (found)
		{
			sig.offset = (void *)paddr;
			break;
		}
		//we're always gonna be on a four byte boundary
		paddr += 1;
		//paddr += sizeof(unsigned long *);
	}

	return sig.offset;
}

