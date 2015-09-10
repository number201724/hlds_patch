#include <Windows.h>

#include "sdk\moduleconfig.h"
#include "sdk\amxxmodule.h"
#include "CSigMngr.h"

#include "detours.h"
#include "LogFile.h"
#include <DbgHelp.h>
#include <TlHelp32.h>
#include <vector>
#include <list>
#include <map>
#include <string>
#include "hl_netchan.h"
using namespace std;
#pragma comment(lib,"dbghelp.lib")
#pragma comment(lib,"wsock32.lib")
typedef int (WINAPI * fnrecvfrom)
	(SOCKET s,
	char* buf,
	int len,
	int flags,
struct sockaddr* from,
	int* fromlen
	);

LogFile* Log;
DWORD blockThread;
typedef struct connect_list_s
{
	sockaddr_in sin;
	int first;
	int block;
}connect_list_t;
typedef struct command_flood_s
{
	DWORD ip;
	DWORD delay;
	int count;
	bool block;
}command_flood_t;
typedef struct fake_connect_s
{
	DWORD ip;
	DWORD connecttime;
}fake_connect_t;
vector <connect_list_t*> List;
//vector <command_flood_t*> FloodList;
vector <fake_connect_t*> FakeList;
HMODULE hSWDS;
HMODULE hMP;


typedef struct queue_packet_s
{
	DWORD timeleft;
	DWORD count;
	unsigned int address;
}queue_packet_t;



list <queue_packet_t*> ConnectPacketList;


DWORD FakePlayerCheckTime=0;
DWORD FakePlayerCheckCount=0;
DWORD FakePlayerCheckInfo=0;
DWORD FakePlayerBanTime=0;

CRITICAL_SECTION m_ConnectCritical;
#define CSDOS_SIG "\x46\x81\xC3\x10\x50\x00\x00\x83\xFE\x20\x7C\xD0"
//#define CSDOS_SIG "\x8D\x4F\x04\x8B\x55\xF8\x51\x8B\xC2\x6A\x1C\x50"
#define CSDOS_SIG_BYTES sizeof(CSDOS_SIG)-1



#define SV_PARSEVOICE "\xB8\x9D\xEF\x51\x66\x8B\xCE\x2B\xCA\xF7\xE9\xC1\xFA\x0D\x8B\xC2\xC1\xE8\x1F\x03\xD0"
#define SV_PARSEVOICE_BYTES sizeof(SV_PARSEVOICE)-1

#define BAD_PARSE "\x55\x8B\xEC\x83\xEC\x18\x56\x57\x33\xFF\x57"
#define BAD_PARSE_BYTES sizeof(BAD_PARSE)-1

#define BOOM_RESLIST "\x75\x0B\x83\x78\x44\x01\x75\x05\x01\x56\x18\xEB\x03\x01\x14\x8E"
#define BOOM_RESLIST_BYTES sizeof(BOOM_RESLIST)-1

#define FAIL_STEAM_LOGIN "\x55\x8B\xEC\x83\xEC\x24\x8B\x45\x08\x53\x57\x50\xE8\xCF\x01\x00\x00"
#define FAIL_STEAM_LOGIN_BYTES sizeof(FAIL_STEAM_LOGIN)-1

#define DLFILE "\x8B\x47\x54\x50\xFF\x57\x58\x8B\x5D\x10"
#define DLFILE_BYTES sizeof(DLFILE)-1

#define SWITCH_ITEM "\x89\x99\xC0\x00\x00\x00\xEB\x0E\x39\xBE\xEC\x05\x00\x00\x75\x06"
#define SWITCH_ITEM_BYTES  sizeof(SWITCH_ITEM)-1

#define SWITCH_ITEM2 "\x8B\x11\xFF\x92\x00\x01\x00\x00\x8B\x8E\xE4\x05\x00\x00\x8B\x01\xFF\x90\x10\x01\x00\x00"
#define SWITCH_ITEM2_BYTES  sizeof(SWITCH_ITEM2)-1

#define BAD_MEMCPY "\x55\x8B\xEC\x8B\x4D\x10\x56\x8B\x75\x0C\x57\x8B\x7D\x08\x8B\xC7\x0B\xC6\x0B\xC1"
#define BAD_MEMCPY_BYTES  sizeof(BAD_MEMCPY)-1

#define DEF_CRASH_15 "\x8B\x01\xFF\x50\x0C\x84\xC0"
#define DEF_CRASH_15_BYTES sizeof(DEF_CRASH_15)-1

#define MEMSET_STRING_15 "\xF3\xAB\x8B\xCE\x83\xC4\x04\x83\xE1\x03\xF3\xAA"
#define MEMSET_STRING_15_BYTES sizeof(MEMSET_STRING_15)-1


#define NET_QUEUE_OVERFLOW "\x8B\x7D\xFC\x83\xC4\x1C\x47\x83\xFF\x02\x89\x7D\xFC"
#define NET_QUEUE_OVERFLOW_BYTES sizeof(NET_QUEUE_OVERFLOW)-1

#define UNK_WPN_NAME "\x8B\x44\x24\x24\x8B\x9A\x98\x00\x00\x00\x03\x18\x6A\x07"
#define UNK_WPN_NAME_BYTES sizeof(UNK_WPN_NAME)-1


#define SV_READCLIENTMSG "\x85\xC0\x74\xD6\x56\xFF\xD0\xEB\xCE"
#define SV_READCLIENTMSG_BYTES sizeof(SV_READCLIENTMSG)-1

#define SZ_WRITE "\x55\x8B\xEC\x8B\x45\x10\x8B\x4D\x0C\x8B\x55\x08\x50\x51\x50\x52"
#define SZ_WRITE_BYTES sizeof(SZ_WRITE)-1

#define FULL_UPDATE "\xE8\xAE\xD0\xF9\xFF\x8D\x45\x98\x50\xE8\xD5\x08\xFA\xFF\x81\xC7\xD0\x4C\x00\x00\x6A\x40\x8D\x4D\x98\x57\x51\xE8\xF3\x08\xFA\xFF"
#define FULL_UPDATE_BYTES sizeof(FULL_UPDATE)-1

#define PATCH_SEH "\x55\x8B\xEC\x8B\x45\x08\x8B\x08\x81\x39\x63\x73\x6D\xE0"
#define PATCH_SEH_BYTES sizeof(PATCH_SEH)-1

#define FRAG_BUFFER_OVERFLOW "\x8B\x0C\x07\x85\xC9\x7C\x2D\x81\xF9\x00\x08\x00\x00\x7F\x25\x8B\x0C\x03\x85\xC9"
#define FRAG_BUFFER_OVERFLOW_BYTES sizeof(FRAG_BUFFER_OVERFLOW)-1

#define FATAL_ERROR "\x55\x8B\xEC\x81\xEC\x00\x04\x00\x00\x8B\x4D\x08\x8D\x45\x0C\x50\x51\x8D\x95\x00\xFC\xFF\xFF\x68\x00\x04\x00\x00\x52\xE8\x2A\x2A\x2A\x2A\xA1\x2A\x2A\x2A\x2A"
#define FATAL_ERROR_BYTES sizeof(FATAL_ERROR)-1

#define SWDS_CREATE_FILE_FRAGMENTS_FUNC "\x55\x8B\xEC\x83\xEC\x2A\x53\x56\x57\x8B\x7D\x0C\xB8\x01\x00\x00\x00\x89\x45\xF4\x89\x45\xF0\x8B\x47\x54\x50\xFF\x57"
#define SWDS_CREATE_FILE_FRAGMENTS_FUNC_BYTES sizeof(SWDS_CREATE_FILE_FRAGMENTS_FUNC)-1

#define SZ_GETSPACE_FUNC "\x55\x8B\xEC\x56\x8B\x75\x08\x57\x8B\x7D\x0C\x8B\x4E\x10\x8B\x46\x0C\x03\xCF\x3B\xC8\x0F\x8E\x93\x00\x00\x00\xF6\x46\x04\x01\x75"
#define SZ_GETSPACE_FUNC_BYTES sizeof(SZ_GETSPACE_FUNC)-1

#define SPLIT_PACKET_FUNC "\x56\x50\xE8\xF7\xFC\xFF\xFF\x83\xC4\x0C\x5F\x5E\x5B\x8B\xE5\x5D\xC3"
#define SPLIT_PACKET_FUNC_BYTES sizeof(SPLIT_PACKET_FUNC)-1



int (* OrigBadParse)(DWORD v1,DWORD v2,DWORD v3);
DWORD BadParse_EBP;
DWORD BadParse_Ret;


char info_value[200][128];
int max_info_value;
void ClearInfoValue()
{
	max_info_value = 0;
	memset(&info_value,0,sizeof(info_value));
}
void InsertInfoValue(char* name)
{
	
	strcpy(info_value[max_info_value],name);
	max_info_value++;

}
bool FindInfoValue(char* name)
{
	for(int i=0;i<max_info_value;i++)
	{
		if(strcmp(info_value[i],name)==0)
		{
			return true;
		}
	}
	return false;
}
bool InfoValueCheck(char* s)
{
	if(strstr(s,"\\\\") || strstr(s,"..") || strstr(s,"\""))
	{
		return false;
	}
	int len = strlen(s);
	int page_count=0;
	for(int x=0;x<len;x++)
	{
		if(s[x] == '\\')
		{
			page_count++;
		}
	}

	if(page_count % 2 != 0) return false;
	ClearInfoValue();

	char* name;
	char* value;
	char* p=s;
	for(int k=0;k<page_count;k++)
	{
		name = strstr(p,"\\");
		if(!name)
			break;
		*name = 0;
		name++;
		value = strstr(name,"\\");
		*value = 0;
		value++;
		p = value;
		if(FindInfoValue(name)) return false;
		InsertInfoValue(name);
	}

	return true;
}

__declspec(naked)void EntryBadParse()
{
	__asm
	{
		mov BadParse_EBP,ebp;
		push [esp];
		pop BadParse_Ret;
		jmp OrigBadParse;
	}
}
__declspec(naked)void LeaveBadParse()
{
	__asm
	{
		mov ebp,esp;
		pop ebp;
		mov ebp,BadParse_EBP;
		add esp,4;
		push BadParse_Ret;
		ret;
	}
}

DWORD g_TickCount = 0;
PVOID pResListRet;
bool __stdcall SafeCheckResCount(DWORD Count)
{
	if(Count>=0 && Count<=8)
		return true;
	return false;
}
__declspec(naked)void _ResourcesList()
{
	__asm
	{
		pushad;
		pushfd;
		push ecx;
		call SafeCheckResCount;
		test al,al;
		je _fix_res_max;
		popfd;
		popad;
		jmp pResListRet;

_fix_res_max:
		popfd;
		popad;
		xor ecx,ecx;
		jmp pResListRet;
	}
}
PVOID pRemovePlayerItem;
__declspec(naked)void _fix_grenade_crash()
{
	__asm
	{
		mov  dword ptr [esi+0x5EC], ebx;
		jmp pRemovePlayerItem;
	}
}
PVOID pSelectLastItem;
__declspec(naked)void _fix_grenade_crash2()
{
	__asm
	{
		test ecx,ecx;
		je _ret;
		test eax,eax;
		je _ret;
		jmp pSelectLastItem;
_ret:
		pop esi;
		add esp,0xC;
		ret;
	}
}
void (*omemcpy)(void* dst,void* src,size_t size);
void m_memcpy_s(void* dst,void* src,size_t size)
{
	if(IsBadWritePtr(dst,size))
		return;
	return omemcpy(dst,src,size);
}

bool CheckLisence(char* szLisence);
typedef struct MEMORY_INFO 
{
	DWORD _EAX;
	DWORD _EBX;
	DWORD _ECX;
	DWORD _EDX;
	DWORD _EBP;
	DWORD _EDI;
	DWORD _ESI;
	DWORD _ESP;
}MEMORY_INFO,*PMEMORY_INFO;
void* pEngineInterface;
MEMORY_INFO gMemoryDump;
DWORD CrashReturn;
int protect=0;
__declspec(naked)void newEngineInterface()
{
	__asm{
		mov gMemoryDump._EBX,ebx;	//保存各个寄存器和返回地址
		mov gMemoryDump._EBP,ebp;
		mov gMemoryDump._ECX,ecx;
		mov gMemoryDump._EDX,edx;
		mov gMemoryDump._EDI,edi;
		mov gMemoryDump._ESI,esi;
		push -1;						//设置异常处理
		push offset NoCrash_Exception;
		push offset NoCrash_Exception; //restore
		pop CrashReturn;
		push fs:[0];
		mov fs:[0],esp;
		mov protect,1;
		call pEngineInterface;
		mov esp,fs:[0]			;	//函数调用完毕,没有Crash
Exception_Return:
		mov protect,0;
		pop dword ptr fs:[0];	//没发现异常
		pop ecx;
		pop ecx	;							//恢复堆栈平衡
		retn;
NoCrash_Exception:					//如果出现异常,进入异常处理嫰数
		mov eax,fs:[0];
		mov esp,eax		;			//修复ESP寄存器

		xor eax,eax	;				//设置继续执行标志位al,
		inc eax;
		mov ebx,gMemoryDump._EBX;		//修复各个寄器的信息
		mov ecx,gMemoryDump._ECX;
		mov edx,gMemoryDump._EDX;
		mov esi,gMemoryDump._ESI;
		mov edi,gMemoryDump._EDI;
		mov ebp,gMemoryDump._EBP;
		jmp Exception_Return;		//执行Sleep指令,执行下一次的封包数据
	}
}


void Netchan_AllocClientPacket(SOCKET s,sockaddr_in* sin,char* p)
{
	char buf[100];

	strcpy(buf,"\xFF\xFF\xFF\xFF\x42\x20");
	strcat(buf,p);

	sendto(s,buf,strlen(buf),0,(sockaddr*)sin,sizeof(sockaddr_in));
}
list<queue_packet_t*>::iterator find_client(sockaddr_in* sock)
{
	list<queue_packet_t*>::iterator Iter;
	for(Iter = ConnectPacketList.begin();Iter!=ConnectPacketList.end();)
	{
		if(sock->sin_addr.S_un.S_addr == (*Iter)->address)
		{
			return Iter;
		}
		++Iter;
	}
	return ConnectPacketList.end();
}
int count_char(char* str,char c)
{
	int count = 0;
	int len = strlen(str);

	for(int i=0;i<len;i++)
	{
		if(str[i] == c)
		{
			count++;
		}
	}
	return count;
}
bool safe_ascii(char* str)
{
	static char ascii_list[] = " ~!@#$%^&*()_+=-{}[]|\\?<>.,;:ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+-";
	int len = strlen(str);

	for(int i=0;i<len;i++)
	{
		bool okstr=false;
		for(int c=0;c<sizeof(ascii_list)-1;c++)
		{
			if(ascii_list[c] == str[i])
			{
				okstr = true;
			}
		}
		if(!okstr)
			return false;
	}
	return true;
}

const BYTE CmpBuf[] = {0x01,0x33,0x31,0x57,0x65,0x65,0x17,0x33,0x17,0x55,0x33,0x70,0x37,0x17,0x37,0x13};
const BYTE CmpBuf2[] = {0x07,0x00,0x00,0x80,0x05,0x00,0x00,0x00,0x3B,0x74,0x64,0x04,0x3D,0x65,0x7C,0x2E,0x61,0x7C,0x21,0x6F,0x70,0x26,0x79,0x2B,0x23,0x71,0x27,0x69,0x7B,0x34,0x43,0x07};

uint32_t msg_readcount = 0;
char packet_data[8192];
uint32_t packet_length;
void MSG_BeginRead(char* packet,uint32_t length)
{
	//packet_data = packet;
	memset(packet_data,0,sizeof(packet_data));
	memcpy(packet_data,packet,length);
	packet_length = length;
	msg_readcount = 0;
}
char *MSG_ReadString (void)
{
	char	*start;
	BOOL    bMore;

	start = (char *)packet_data + msg_readcount;

	for ( ; msg_readcount < packet_length ; msg_readcount++)
		if (((packet_data[msg_readcount] == '\r') ||
		     (packet_data[msg_readcount] == '\n'))
		|| packet_data[msg_readcount] == 0)
			break;

	bMore = packet_data[msg_readcount] != '\0';

	packet_data[msg_readcount] = 0;
	msg_readcount++;

	// skip any \r\n
	if (bMore)
	{
		while (packet_data[msg_readcount] == '\r' ||
			   packet_data[msg_readcount] == '\n')
		{
		   msg_readcount++;
		};

	}
	return start;
}

unsigned char MSG_ReadByte( void )
{
	unsigned char *c;

	if ( msg_readcount >= packet_length )
	{
		//printf( "Overflow reading byte\n" );
		return (unsigned char)-1;
	}

	c = (unsigned char *)packet_data + msg_readcount;
	msg_readcount += sizeof( unsigned char );

	return *c;
}

unsigned short MSG_ReadShort( void )
{
	unsigned char *c;
	unsigned short r;

	if ( msg_readcount >= packet_length )
	{
		//printf( "Overflow reading short\n" );
		return (unsigned short)-1;
	}

	c = (unsigned char *)packet_data + msg_readcount;
	msg_readcount += sizeof( unsigned short );

	r = *(unsigned short *)c;

	return r;
}

unsigned int MSG_ReadLong( void )
{
	unsigned char *c;
	unsigned int r;

	if ( msg_readcount >= packet_length )
	{
		//printf( "Overflow reading int\n" );
		return (unsigned int)-1;
	}

	c = (unsigned char *)packet_data + msg_readcount;
	msg_readcount += sizeof( unsigned int );

	r = *(unsigned int *)c;

	return r;
}

int check_param(char* lpBuffer,int BufferLength)
{
	ULONG Index;
	MSG_BeginRead(lpBuffer,BufferLength);
	Index = MSG_ReadLong();
	char* connect_info = MSG_ReadString();

	connect_info += 8; //connect\x20

	if(strncmp(connect_info,"46",2)!=0)
		return 0;
	connect_info += 3;
	int maxlen = strlen(connect_info);
	int len=0;

	//info session
	for(len=0;len<maxlen;len++)
	{
		if(connect_info[len] == ' ')
		{
			connect_info[len] = 0;
			len ++;
			connect_info += len;
			len = -1;
			break;
		}
	}

	if(len != -1)
	{
		return 0;
	}

	
	if(*connect_info != '\"')
	{
		return 0;
	}
	connect_info++;
	char* start = connect_info;
	char* end = strstr(start,"\"");
	if(!end) return 0;
	*end = 0;



	if(!safe_ascii(start)) return 0;

	if(!InfoValueCheck(start)) return 0;
	connect_info = end;
	*connect_info = 0;
	connect_info++;


	if(connect_info[0] != ' ') return 0;
	connect_info++;
	if(connect_info[0] != '\"') return 0;
	connect_info++;
	start = connect_info;
	end = strstr(start,"\"");
	if(!end) return 0;
	end[0] = 0;

	if(!safe_ascii(start)) return 0;
	
	if(!InfoValueCheck(start)) return 0;

	return 1;

}

int WINAPI newrecvfrom(SOCKET s,char* buf,int len,int flags,struct sockaddr* from,int* fromlen)
{
	bool block=false;
	vector<connect_list_t*>::iterator iter;
	PBYTE nbuf = (PBYTE)buf;
	Retry_Recv:
	int result = recvfrom(s,buf,len,flags,from,fromlen);
	sockaddr_in* sockaddr_p = (sockaddr_in*)from;

	if(GetCurrentThreadId() == blockThread)
	{
		if(result > 0)
		{
			/*if(memcmp(buf,CmpBuf,sizeof(CmpBuf)-1)==0 ||
				memcmp(buf,CmpBuf2,sizeof(CmpBuf2)-1)==0)
			{
				WSASetLastError(WSAEWOULDBLOCK);
				return -1;
			}*/
			if(*(DWORD*)buf == -1)
			{
				if (!( (buf[4] >= 'A' && buf[4] <= 'Z') || (buf[4] >= 'a' && buf[4] <= 'z') ))
				{
					goto Retry_Recv;
					//WSASetLastError(WSAEWOULDBLOCK);
					//return -1;
				}
				if(strncmp(&buf[4],"connect",7)==0)
				{
					//if(result <= 20)
					//{
					//	goto Retry_Recv;
					//	WSASetLastError(WSAEWOULDBLOCK);
					//	return -1;
					//}
					if(!check_param(buf,result))
					{
						goto Retry_Recv;
						WSASetLastError(WSAEWOULDBLOCK);
						return -1;
					}

					if(FakePlayerCheckInfo)
					{
						list <queue_packet_t*>::iterator Iter = find_client((sockaddr_in*)from);
						if(Iter != ConnectPacketList.end())
						{
							switch(FakePlayerCheckInfo)
							{
							case 1:
								{
									(*Iter)->count++;
									if((*Iter)->count >= FakePlayerCheckCount)
									{
										char szBanCommand[128];
										sprintf(szBanCommand,"addip %u %s;",FakePlayerBanTime,inet_ntoa(sockaddr_p->sin_addr));
										g_engfuncs.pfnServerCommand(szBanCommand);
										delete *Iter;
										ConnectPacketList.erase(Iter);
										WSASetLastError(WSAEWOULDBLOCK);
										return -1;
									}
									break;
								}
							case 2:
								{
									if((*Iter)->count >= FakePlayerCheckCount)
									{
										unsigned char send_packet[128];
										memset(&send_packet,0,sizeof(send_packet));
										char kick_msg[128];
										int second = FakePlayerCheckTime / 1000;
										sprintf(kick_msg,"[NoCrash]%d miao nei lian jie chao guo %d ci,qing deng dai %d miao!!!\n",second,FakePlayerCheckCount,second);

										send_packet[0] = 0xFF;
										send_packet[1] = 0xFF;
										send_packet[2] = 0xFF;
										send_packet[3] = 0xFF;
										send_packet[4] = 'l';
										strcat((char*)&send_packet,kick_msg);
										sendto(s,(char*)&send_packet,strlen((char*)&send_packet),0,from,sizeof(sockaddr_in));
										(*Iter)->timeleft = GetTickCount();

										WSASetLastError(WSAEWOULDBLOCK);
										return -1;
									}
									(*Iter)->count++;
									break;
								}
							default:
								break;
							}
						}
						queue_packet_t *queue_packet = new queue_packet_t;
						queue_packet->address = ((sockaddr_in*)from)->sin_addr.S_un.S_addr;
						queue_packet->timeleft = GetTickCount();
						queue_packet->count=1;
						ConnectPacketList.push_back(queue_packet);
					}
				}
			}
		}
	}
	return result;
}
static void DumpMiniDump(HANDLE hFile, PEXCEPTION_POINTERS excpInfo)
{
	MINIDUMP_EXCEPTION_INFORMATION eInfo;
	eInfo.ThreadId = GetCurrentThreadId(); //把需要的信息添进去
	eInfo.ExceptionPointers = excpInfo;
	eInfo.ClientPointers = FALSE;
	MiniDumpWriteDump(
		GetCurrentProcess(),
		GetCurrentProcessId(),
		hFile,
		MiniDumpNormal,
		excpInfo ? &eInfo : NULL,
		NULL,
		NULL);
}

void HookImport(HMODULE hModule,DWORD OriginAPI,DWORD newAPI)
{
	PBYTE pImage = (PBYTE)hModule;
	PIMAGE_DOS_HEADER pImageDos;
	PIMAGE_NT_HEADERS pImageNT;
	PIMAGE_DATA_DIRECTORY pDataDirectory;
	PIMAGE_IMPORT_DESCRIPTOR pImportDescriptor;
	pImageDos = (PIMAGE_DOS_HEADER)pImage;
	pImageNT = (PIMAGE_NT_HEADERS)&pImage[pImageDos->e_lfanew];

	pDataDirectory = &pImageNT->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	if(!pDataDirectory->VirtualAddress)
		return;

	pImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)&pImage[pDataDirectory->VirtualAddress];
	try
	{
		for(int i=0;pImportDescriptor[i].Characteristics!=0;i++)
		{
			HMODULE hCurrentModule = LoadLibrary((LPCSTR)(&pImage[pImportDescriptor[i].Name]));
			PIMAGE_THUNK_DATA32 pCurrentImportThunk = (PIMAGE_THUNK_DATA32)(&pImage[pImportDescriptor[i].OriginalFirstThunk]);
			FARPROC* pCurrentImportList = (FARPROC*)(&pImage[pImportDescriptor[i].FirstThunk]);
			for(int m_imp=0;pCurrentImportThunk[m_imp].u1.AddressOfData!=0;m_imp++)
			{
				if(IMAGE_SNAP_BY_ORDINAL32(pCurrentImportThunk[m_imp].u1.AddressOfData))
				{
					if(pCurrentImportList[m_imp] == (FARPROC)OriginAPI)
					{
						DWORD oldProtect;
						VirtualProtect(&pCurrentImportList[m_imp],4,PAGE_EXECUTE_READWRITE,&oldProtect);
						pCurrentImportList[m_imp] = (FARPROC)newAPI;
					}
				}else
				{
					if(pCurrentImportList[m_imp] == (FARPROC)OriginAPI)
					{
						DWORD oldProtect;
						VirtualProtect(&pCurrentImportList[m_imp],4,PAGE_EXECUTE_READWRITE,&oldProtect);
						pCurrentImportList[m_imp] = (FARPROC)newAPI;
					}
				}
			}
		}
	}catch(...){};
	return;
}
DWORD MainThreadId;
typedef bool (__stdcall * fnRtlDispatchException)(PEXCEPTION_RECORD pExcptRec,PCONTEXT pContext);
fnRtlDispatchException gOriginRtlDispatchException;
DWORD exception_swds = NULL;
DWORD exception_mp = NULL;
DWORD exception_swds_end = NULL;
DWORD exception_mp_end = NULL;
DWORD GetPEImageSize(HMODULE hModule)
{
	PBYTE pInfo = (PBYTE)hModule;
	PIMAGE_DOS_HEADER pImgDos = (PIMAGE_DOS_HEADER)pInfo;
	PIMAGE_NT_HEADERS pImgNt;
	if(pImgDos->e_magic==IMAGE_DOS_SIGNATURE)
	{
		pImgNt = (PIMAGE_NT_HEADERS)&pInfo[pImgDos->e_lfanew];
		if(pImgNt)
		{
			if(pImgNt->Signature==IMAGE_NT_SIGNATURE)
			{
				return pImgNt->OptionalHeader.SizeOfImage;
			}
		}
	}
	return NULL;
}
DWORD GetPEImageEnd(HMODULE hModule)
{
	if(!hModule)
		return NULL;
	return ((DWORD)hModule + GetPEImageSize(hModule));
}
bool __stdcall newRtlDispatchException(PEXCEPTION_RECORD ExceptionRecord,PCONTEXT ContextRecord)
{
	bool bstatus = gOriginRtlDispatchException(ExceptionRecord,ContextRecord);
	if(protect==1)
	{
		if(GetCurrentThreadId() == MainThreadId && !bstatus)
		{
			if(!exception_swds)
			{
				exception_swds = (DWORD)GetModuleHandle("swds.dll");
				exception_swds_end = GetPEImageEnd(GetModuleHandle("swds.dll"));
			}
			if(!exception_mp)
			{
				exception_mp = (DWORD)GetModuleHandle("mp.dll");
				exception_mp_end = GetPEImageEnd(GetModuleHandle("mp.dll"));
			}

			EXCEPTION_POINTERS ExceptionInfo;
			MINIDUMP_EXCEPTION_INFORMATION eInfo;

			ExceptionInfo.ContextRecord = ContextRecord;
			ExceptionInfo.ExceptionRecord = ExceptionRecord;

			eInfo.ThreadId = GetCurrentThreadId();
			eInfo.ExceptionPointers = &ExceptionInfo;
			eInfo.ClientPointers = FALSE;

			SYSTEMTIME stCurTime;
			::GetLocalTime(&stCurTime);								// 获取当前系统时间
			char sDate[128] = { 0 };
			_snprintf(sDate, 127, "崩溃存储_%04d_%d_%02d_%02d_%02d_%02d.mdmp", stCurTime.wYear, stCurTime.wMonth, stCurTime.wDay, stCurTime.wHour, stCurTime.wMinute, stCurTime.wSecond);
			HANDLE hFile = CreateFile(sDate, GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL ); 
			MiniDumpWriteDump(GetCurrentProcess(), GetCurrentProcessId(), hFile, MiniDumpNormal, &eInfo, NULL, NULL);
			CloseHandle(hFile);

			ContextRecord->Eip = CrashReturn;
			return true;
		}
	}
	
	return bstatus;
}
void* pNET_Queue_Overflow;
void __stdcall ban_player(char* ipaddr)
{
	char szip[64];

	strcpy(szip,ipaddr);
	int len = strlen(szip);
	for(int i=0;i<len;i++)
	{
		if(szip[i] == ':')
		{
			szip[i] = 0;
			break;
		}
	}
	/*char command[64];
	sprintf(command,"addip 0 %s;",szip);

	g_engfuncs.pfnServerCommand(command);*/
}
__declspec(naked)void _patch_net_queue_overflow()
{
	__asm
	{
		pushad
		push eax
		call ban_player
		popad
		jmp pNET_Queue_Overflow
	}
}
void* pDeathNotice;
void* pDeathNotice2;
int __stdcall safe_check(char* wpn_name)
{
	if(IsBadReadPtr((const void*)wpn_name,7))
		return 1;
	return 0;
}
__declspec(naked)void unk_wpn_name_patch()
{
	__asm
	{
		test eax,eax
		jne _ret
_bad_read:
		pop edi
		pop esi
		pop ebp
		pop ebx
		add esp,8
		retn 0xC
_ret:
		pushad
		push eax
		call safe_check
		cmp eax,1
		popad
		je _bad_read
		popad
		jmp pDeathNotice
	}
}
__declspec(naked)void unk_wpn_name_patch2()
{
	__asm
	{
		test eax,eax
		jne _ret
_bad_read:
		pop edi
		pop esi
		pop ebp
		pop ebx
		add esp,8
		retn 0xC
_ret:
		pushad
		push eax
		call safe_check
		cmp eax,1
		popad
		je _bad_read
		popad
		jmp pDeathNotice2
	}
}

void SZ_Clear (sizebuf_t *buf)
{
	buf->cursize = 0;
	buf->flags |= FSB_OVERFLOWED;
}
typedef void *(*fnSZ_GetSpace) (sizebuf_t *buf, int length);
fnSZ_GetSpace pSZ_GetSpace;
static unsigned char SpaceData[10000];
void *SZ_GetSpace (sizebuf_t *buf, int length)
{
	void *data;
	
	return pSZ_GetSpace(buf,length);
	if (buf->cursize + length > buf->maxsize)
	{
		//允许溢出,走原始函数
		if( buf->flags & FSB_ALLOWOVERFLOW)
			return pSZ_GetSpace(buf,length);
		//不允许溢出(服务器崩溃了),则清空数据
		//buf->flags |= FSB_OVERFLOWED;
		//SZ_Clear (buf);
	}

	data = buf->data + buf->cursize;
	buf->cursize += length;
	
	return data;
}

__declspec(naked)void _strncmp_safe()
{
	__asm
	{
		pushad
		push ebx
		call safe_check
		cmp eax,1
		je _bad_read
		popad
		
		jmp strncmp

_bad_read:
		popad
		add esp,0x10
		pop edi
		pop esi
		pop ebp
		pop ebx
		add esp,8
		retn 0xC
	}
}
void InitExceptionFilter()
{
	DWORD oldProtect;
	PBYTE pFarProc = (PBYTE)GetProcAddress(LoadLibrary("ntdll.dll"),"KiUserExceptionDispatcher");

	for(DWORD i=0;i<40;i++)
	{
		if(*(pFarProc+i)==0xE8)
		{
			gOriginRtlDispatchException = (fnRtlDispatchException)((DWORD)(pFarProc+i) + *(DWORD*)(pFarProc+i+1) + 5);
			VirtualProtect((PVOID)(pFarProc+i),6,PAGE_EXECUTE_READWRITE,&oldProtect);
			*(DWORD*)(pFarProc+i+1) = (DWORD)&newRtlDispatchException - (DWORD)(pFarProc+i) - 5;			
			break;
		}
	}
}
typedef char* (*fnget_command)();
fnget_command pget_command;
char* command;
char client_command[1024];
char* get_command()
{
	command = pget_command();
	strcpy(client_command,command);
	_strlwr(client_command);
	if(strstr(client_command,"halflife.wad")!=NULL)
	{
		return "";
	}
	return command;
}
typedef void (*fnclc_stringcmd)(DWORD* client_t);
fnclc_stringcmd pclc_stringcmd;
//10 = ip
//13 = port(HIWORD)
typedef struct player_ban_count
{
	DWORD frame_time;
	DWORD count;
}player_ban_count;
map <DWORD,player_ban_count*> g_PlayerUpdate;
void clc_stringcmd(DWORD* client_t)
{
	DWORD userip = client_t[10];
	DWORD c;
	pclc_stringcmd(client_t);
	strlwr(client_command);
	if(strncmp(client_command,"setinfo",7)==0 || strncmp(client_command,"fullupdate",10)==0)
	{
		
		map <DWORD,player_ban_count*>::iterator Iter = g_PlayerUpdate.find(userip);
		if(Iter != g_PlayerUpdate.end())
		{
			Iter->second->count++;
			Iter->second->frame_time = GetTickCount();
			c = Iter->second->count;
		}
		else
		{
			player_ban_count* info = new player_ban_count;
			info->frame_time = GetTickCount();
			info->count = 1;
			g_PlayerUpdate[userip] = info;
			c = 1;
		}

		if(c > FakePlayerCheckCount)
		{
			char szBanCommand[64];
			in_addr addr;
			addr.S_un.S_addr = userip;
			//sprintf(szBanCommand,"addip 1 %s;",inet_ntoa(addr));
			//g_engfuncs.pfnServerCommand(szBanCommand);
		}
	}
}
void ClearFakePlayerList(DWORD lastFrame)
{
	list<queue_packet_t*>::iterator Iter;
	if(FakePlayerCheckInfo)
	{
		for(Iter = ConnectPacketList.begin();Iter != ConnectPacketList.end();)
		{
			uint32_t timeleft = lastFrame - (*Iter)->timeleft;
			if(timeleft > 0)
			{
				if(timeleft > FakePlayerCheckTime)
				{
					delete *Iter;
					Iter = ConnectPacketList.erase(Iter);
					continue;
				}
			}
			++Iter;
		}
	}
}
void ClearHackCommandList(DWORD lastFrame)
{
	map <DWORD,player_ban_count*>::iterator Iter;
	for(Iter = g_PlayerUpdate.begin();Iter != g_PlayerUpdate.end();)
	{
		int timeleft;
		timeleft = lastFrame - Iter->second->frame_time;
		if(timeleft > 0)
		{
			if(timeleft > 10000)
			{
				delete Iter->second;
				Iter = g_PlayerUpdate.erase(Iter);
				continue;
			}
		}
		++Iter;
	}
}
void FN_StartFrame(void)
{
	DWORD lastFrame = GetTickCount();
	ClearFakePlayerList(lastFrame);
	ClearHackCommandList(lastFrame);
	RETURN_META(MRES_IGNORED);
}

typedef void (*fnMSG_WriteString)(sizebuf_t *sb, char *s);
typedef void (*fnMSG_WriteLong)(sizebuf_t *sb,int u);
fnMSG_WriteString pMSG_WriteString;
int player_uid=0;
void MyMSG_WriteString(sizebuf_t *sb, char *s)
{
	char ws[512];
	
	if(strlen(s)==0)
	{
		return pMSG_WriteString(sb,s);
	}
	strcpy(ws,s);
	if(!InfoValueCheck(ws))
	{
		return pMSG_WriteString(sb,"");
	}
	return pMSG_WriteString(sb,s);
}
fnMSG_WriteLong pMSG_WriteLong;
void MyMSG_WriteLong(sizebuf_t *sb,int u)
{
	player_uid = u;
	return pMSG_WriteLong(sb,u);
}

typedef void (*fnSV_Error)(const char*);
fnSV_Error fatal_error;
// 写日志函数
void WriteLog(const char *szfileName, const char *szMsgStr)
{
	std::string fileStr = szfileName;
	fileStr += ".log";
	LogFile tmpLog(fileStr.c_str());
	SYSTEMTIME now;
	GetLocalTime(&now);
	char tempLog[256];
	memset(tempLog, 0, sizeof(tempLog));
	sprintf(tempLog, "%d-%d-%d %d:%d:%d ", now.wYear, now.wMonth,
		now.wDay, now.wHour, now.wMinute, now.wSecond);
	std::string tmpLogStr = tempLog;
	tmpLogStr += szMsgStr;
	tmpLog.Log(tmpLogStr.c_str());
}
void newSV_Error(const char* error)
{
	WriteLog("FatalError",error);
}
void ReadFakePlayerConfig(char* szConfig)
{
	FakePlayerCheckTime = GetPrivateProfileInt("假人攻击防御","连接检测时间",10000,szConfig);
	FakePlayerCheckCount = GetPrivateProfileInt("假人攻击防御","检测时间内次数",8,szConfig);
	FakePlayerCheckInfo = GetPrivateProfileInt("假人攻击防御","封禁玩家",2,szConfig);
	FakePlayerBanTime = GetPrivateProfileInt("假人攻击防御","封禁时间",10,szConfig);
}
void* split_packet;
uint32_t length_4byte;
int check_length()
{
	if(length_4byte < 1023)
		return 1;
	return 0;
}
int* buf_length;

int WINAPI SplitSafeCheck(unsigned char* buf)
{
	if(*buf_length != 9)
		return 0;
	unsigned char n = buf[8];
	n &= 0xFF;
	unsigned char h,l;
	h = n >> 4;
	l = n & 0xF;
	if ( l > 5 || h > 4 )
	{
		return 0;
	}
	if((1391 * h) > 0xFAA) return 0;
	return 1;
}
__declspec(naked)void CopySplitPacket()
{
	__asm
	{
		pop buf_length
		pushad
		push eax
		call SplitSafeCheck
		cmp eax,1
		
		popad
		je OrgRet
		
		pop edi
		pop esi
		pop ebx
		mov esp,ebp
		pop ebp
		retn
OrgRet:
		push buf_length
		jmp split_packet
		
	}
}
void OnAmxxAttach()
{
	char szConfig[MAX_PATH];
	char szConfigCode[41];

	MainThreadId = GetCurrentThreadId();
	GetCurrentDirectory(sizeof(szConfig),szConfig);
	strcat(szConfig,"\\hlds_patch.ini");

	GetPrivateProfileString("hlds_patch","服务器注册码","",(LPSTR)&szConfigCode,sizeof(szConfigCode),szConfig);

	int CrashType = GetPrivateProfileInt("崩溃处理","处理状态",1,szConfig);
	blockThread = GetCurrentThreadId();
	if(CheckLisence(szConfigCode))
	{
		InitializeCriticalSection(&m_ConnectCritical);
		g_engfuncs.pfnServerPrint("服务器注册成功 开始补丁程序\n");
		ReadFakePlayerConfig(szConfig);
		char szLogName[MAX_PATH];
		GetCurrentDirectory(sizeof(szLogName),szLogName);
		strcat(szLogName,"\\NoCrashLog.log");
		Log = new LogFile(szLogName);

		hSWDS = GetModuleHandle("swds.dll");
		hMP = GetModuleHandle("mp.dll");

		/*PVOID CSDOSPatch = FIND_MEMORY(hSWDS,CSDOS_SIG);
		if(CSDOSPatch)
		{
			*(DWORD*)&CSDOSPatch = (DWORD)CSDOSPatch - 2;
			BYTE bCSDOS_OPCODE[] = {0xEB,0x0C};
			pmemcpy(CSDOSPatch,&bCSDOS_OPCODE,2);
		}*/

		PVOID ParseVoicePatch = FIND_MEMORY(hSWDS,SV_PARSEVOICE);
		if(ParseVoicePatch)
		{
			*(DWORD*)&ParseVoicePatch = (DWORD)ParseVoicePatch + 0x27;
			SetNopCode(ParseVoicePatch,13);
		}

		PVOID pResList = FIND_MEMORY(hSWDS,BOOM_RESLIST);
		if(pResList)
		{
			pResListRet = pResList;
			DetourTransactionBegin();
			DetourUpdateThread(GetCurrentThread());
			DetourAttach((void**)&pResListRet,_ResourcesList);
			DetourTransactionCommit();
		}

		PVOID pSteamLogin = FIND_MEMORY(hSWDS,FAIL_STEAM_LOGIN);

		if(pSteamLogin)
		{
			BYTE FillCode[] = {0x33,0xC0,0xC3};
			pmemcpy(pSteamLogin,&FillCode,3);
		}

		PVOID pDlFileFix = FIND_MEMORY(hSWDS,DLFILE);

		if(pDlFileFix)
		{
			BYTE FillData[] ={0x6A,0x00,0xB8,0x00,0x04,0x00,0x00};
			pmemcpy(pDlFileFix,&FillData,sizeof(FillData));
		}

		pNET_Queue_Overflow = FIND_MEMORY(hSWDS,NET_QUEUE_OVERFLOW);

		if(pNET_Queue_Overflow)
		{
			pNET_Queue_Overflow = (PVOID)((DWORD)pNET_Queue_Overflow - 5);
			DetourTransactionBegin();
			DetourUpdateThread(GetCurrentThread());
			DetourAttach((void**)&pNET_Queue_Overflow,_patch_net_queue_overflow);
			DetourTransactionCommit();
		}
		DWORD fixer = (DWORD)FIND_MEMORY(hSWDS,FULL_UPDATE);
		if(fixer)
		{
			__asm
			{
				mov eax,fixer;
				add eax,dword ptr [eax+1];
				add eax,5;
				mov pMSG_WriteString,eax
			}
			DWORD oldProtect;
			VirtualProtect((LPVOID)(fixer-100),0x1000,PAGE_EXECUTE_READWRITE,&oldProtect);
			__asm
			{
				lea eax,MyMSG_WriteString
				sub eax,fixer
				sub eax,5
				mov ecx,fixer
				mov dword ptr [ecx+1],eax

				mov eax,fixer
				sub eax,0xD
				
				push eax
				mov ecx,[eax+1]
				add eax,ecx
				add eax,5
				mov pMSG_WriteLong,eax
				pop eax
				lea ecx,MyMSG_WriteLong
				sub ecx,eax
				sub ecx,5
				mov dword ptr [eax+1],ecx
			}
		}

		void* FragBufferCheck = FIND_MEMORY(hSWDS,FRAG_BUFFER_OVERFLOW);

		if(FragBufferCheck)
		{
#define OLD_OPCODE "\x8B\x0C\x07\x85\xC9\x7C\x2D\x81\xF9\x78\x05\x00\x00\x7F\x25\x8B\x0C\x03\x85\xC9"

			DWORD oldProtect;
			VirtualProtect(FragBufferCheck,20,PAGE_EXECUTE_READWRITE,&oldProtect);
			memcpy(FragBufferCheck,OLD_OPCODE,sizeof(OLD_OPCODE)-1);
		}
		//FRAG_BUFFER_OVERFLOW

		/*pDeathNotice = FIND_MEMORY(hMP,UNK_WPN_NAME);
		DWORD new_addr;
		if(pDeathNotice)
		{
			DWORD oldProtect;
			__asm add pDeathNotice,4;
			new_addr = (DWORD)pDeathNotice;

			VirtualProtect((LPVOID)new_addr,100,PAGE_EXECUTE_READWRITE,&oldProtect);
			__asm
			{
				pushad
				mov eax,pDeathNotice
				add eax,0x10

				lea ecx,_strncmp_safe
				sub ecx,eax
				sub ecx,5
				mov dword ptr[eax+1],ecx
				popad
			}

			DetourTransactionBegin();
			DetourUpdateThread(GetCurrentThread());
			DetourAttach((void**)&pDeathNotice,unk_wpn_name_patch);
			DetourTransactionCommit();

			new_addr -= 0x12;

			pDeathNotice2 = (void*)new_addr;

			DetourTransactionBegin();
			DetourUpdateThread(GetCurrentThread());
			DetourAttach((void**)&pDeathNotice2,unk_wpn_name_patch2);
			DetourTransactionCommit();
		}*/

		/*omemcpy = (void (__cdecl *)(void *,void *,size_t))FIND_MEMORY(hSWDS,BAD_MEMCPY);

		if(omemcpy)
		{
			DetourTransactionBegin();
			DetourUpdateThread(GetCurrentThread());
			DetourAttach((void**)&omemcpy,m_memcpy_s);
			DetourTransactionCommit();
		}*/
		fatal_error = (fnSV_Error)FIND_MEMORY(hSWDS,FATAL_ERROR);
		if(fatal_error)
		{
			DetourTransactionBegin();
			DetourUpdateThread(GetCurrentThread());
			DetourAttach((void**)&fatal_error,newSV_Error);
			DetourTransactionCommit();
		}

		pSZ_GetSpace = (fnSZ_GetSpace)FIND_MEMORY(hSWDS,SZ_GETSPACE_FUNC);
		if(pSZ_GetSpace)
		{
			DetourTransactionBegin();
			DetourUpdateThread(GetCurrentThread());
			DetourAttach((void**)&pSZ_GetSpace,SZ_GetSpace);
			DetourTransactionCommit();
		}

		split_packet = FIND_MEMORY(hSWDS,SPLIT_PACKET_FUNC);
		if(split_packet)
		{
			DetourTransactionBegin();
			DetourUpdateThread(GetCurrentThread());
			DetourAttach((void**)&split_packet,CopySplitPacket);
			DetourTransactionCommit();
			//CopySplitPacket
		}
	
		PBYTE pSWDS = (PBYTE)GetModuleHandle("swds.dll");
		if(pSWDS)
		{
			pSWDS += 0x1000;
			DWORD* pList = (DWORD*)	FIND_MEMORY(pSWDS,SV_READCLIENTMSG);
			if(pList)
			{
				bool done=false;
				pList--;

				DWORD* pFuncList = (DWORD*)*pList;
				pFuncList++;
				if(*pFuncList == 1)
				{
					do
					{
						if(strcmp((char*)pFuncList[1],"clc_stringcmd")==0)
						{
							pclc_stringcmd = (fnclc_stringcmd)pFuncList[2];
							pFuncList[2] = (DWORD)clc_stringcmd;
							PBYTE pcall = (PBYTE)((DWORD)pclc_stringcmd + 1);
							if(pcall[0] == 0xE8)
							{
								DWORD oldProtect;
								pget_command = (fnget_command)(pcall + 5 + *(DWORD*)&pcall[1]);
								VirtualProtect((LPVOID)pcall,5,PAGE_EXECUTE_READWRITE,&oldProtect);
								*(DWORD*)&pcall[1] = (DWORD)get_command - (DWORD)pcall - 5;
							}
							break;
						}
						pFuncList += 3;
					}while(*pFuncList!=0);
				}
			}
		}

		void* PatchSEH = FIND_MEMORY(GetModuleHandle(NULL),PATCH_SEH);
		if(PatchSEH)
		{
			DWORD oldProtect;
			VirtualProtect(PatchSEH,10,PAGE_EXECUTE_READWRITE,&oldProtect);
			memcpy(PatchSEH,"\x55\x8B\xEC\xEB\x44\x90",6);
		}

		switch(CrashType)
		{
		case 1:
			InitExceptionFilter();
			break;
		case 2:
			{
				InitExceptionFilter();
				void* pCrashSig = FIND_MEMORY(GetModuleHandle(NULL),DEF_CRASH_15);
				void* pBakCrashSig;
				if(pCrashSig)
				{
					pBakCrashSig = pCrashSig;
					DWORD OldProtect;
					__asm
					{
						mov edx,pCrashSig;
						sub edx,6;
						inc edx;
						inc edx;
						mov edx,[edx];
						mov edx,[edx];
						mov edx,[edx];
						mov edx,[edx+0xC];
						mov pEngineInterface,edx;
					}
					DetourTransactionBegin();
					DetourUpdateThread(GetCurrentThread());
					DetourAttach((void**)&pCrashSig,newEngineInterface);
					DetourTransactionCommit();


					VirtualProtect(pBakCrashSig,1,PAGE_EXECUTE_READWRITE,&OldProtect);

					((PBYTE)pBakCrashSig)[0] = 0xE8;
				}
			break;
			}
		}
		

		g_engfuncs.pfnServerPrint("服务器补丁程序完成\n");

		HookImport(hSWDS,(DWORD)GetProcAddress(GetModuleHandle("wsock32.dll"),"recvfrom"),(DWORD)&newrecvfrom);
	}
}

void OnPluginsLoaded()
{

}
void OnAmxxDetach()
{
	
}