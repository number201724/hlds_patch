#include "moduleconfig.h"
#include "amxxmodule.h"
#include "CSigMngr.h"

/*
0E2AFF00    8B4424 04       mov     eax, dword ptr [esp+4]
0E2AFF04    56              push    esi
0E2AFF05    57              push    edi
0E2AFF06    8BF9            mov     edi, ecx
0E2AFF08    8B0D 9425360E   mov     ecx, dword ptr [E362594]         ; hl.02517D60
0E2AFF0E    2B81 98000000   sub     eax, dword ptr [ecx+98]
0E2AFF14    50              push    eax
0E2AFF15    E8 066FFBFF     call    0E266E20
0E2AFF1A    8BF0            mov     esi, eax
0E2AFF1C    83C4 04         add     esp, 4
0E2AFF1F    85F6            test    esi, esi                         ; if (!pent)
0E2AFF21    74 0E           je      short 0E2AFF31
0E2AFF23    56              push    esi
0E2AFF24    FF15 3824360E   call    dword ptr [E362438]              ; metamod.6B220D88
0E2AFF2A    83C4 04         add     esp, 4
0E2AFF2D    85C0            test    eax, eax
0E2AFF2F    75 15           jnz     short 0E2AFF46                   ; if(!ENullEnt(pent))
0E2AFF31    68 401A320E     push    0E321A40                         ; ASCII "NULL Ent in GiveNamedItem!",LF
0E2AFF36    6A 01           push    1
0E2AFF38    FF15 1424360E   call    dword ptr [E362414]              ; metamod.6B21E5BC
0E2AFF3E    83C4 08         add     esp, 8
0E2AFF41    5F              pop     edi
0E2AFF42    5E              pop     esi
0E2AFF43    C2 0400         retn    4
0E2AFF46    8B57 04         mov     edx, dword ptr [edi+4]
0E2AFF49    8D86 88000000   lea     eax, dword ptr [esi+88]
0E2AFF4F    83C2 08         add     edx, 8
0E2AFF52    56              push    esi
0E2AFF53    8B0A            mov     ecx, dword ptr [edx]
0E2AFF55    8908            mov     dword ptr [eax], ecx
0E2AFF57    8B4A 04         mov     ecx, dword ptr [edx+4]
0E2AFF5A    8948 04         mov     dword ptr [eax+4], ecx
0E2AFF5D    8B52 08         mov     edx, dword ptr [edx+8]
0E2AFF60    8950 08         mov     dword ptr [eax+8], edx
0E2AFF63    8B96 20020000   mov     edx, dword ptr [esi+220]
0E2AFF69    81CA 00000040   or      edx, 40000000
0E2AFF6F    8996 20020000   mov     dword ptr [esi+220], edx
0E2AFF75    E8 C676FBFF     call    0E267640
0E2AFF7A    8B47 04         mov     eax, dword ptr [edi+4]
0E2AFF7D    8B88 08020000   mov     ecx, dword ptr [eax+208]
0E2AFF83    51              push    ecx
0E2AFF84    56              push    esi
0E2AFF85    E8 0679FBFF     call    0E267890
0E2AFF8A    83C4 0C         add     esp, 0C
0E2AFF8D    5F              pop     edi
0E2AFF8E    5E              pop     esi
0E2AFF8F    C2 0400         retn    4
*/

#define MP_FNULLENT "\x8B\x0A\x89\x08\x8B\x4A\x04\x89\x48\x04\x8B\x52\x08\x89\x50\x08\x8B\x96\x20\x02\x00\x00"
#define MP_FNULLENT_BYTES sizeof(MP_FNULLENT)-1
void* mem_orig_fullent_func;
int newEntOffsetOfPEntity(const edict_t *pEdict)
{
	if(pEdict->free)
		return NULL;
	return ((int (*)(const edict_t *pEdict))mem_orig_fullent_func)(pEdict);
}
void PatchFNullEnt(PDWORD pData)
{
	mem_orig_fullent_func = (void*)*pData;

	*pData = (DWORD)&newEntOffsetOfPEntity;
}
void OnAmxxAttach()
{
	void* p1 = FIND_MEMORY(GetModuleHandle("mp.dll"),MP_FNULLENT);

	if(p1)
	{
		PatchFNullEnt((PDWORD)*(DWORD*)((DWORD)p1 - 45));
	}
}