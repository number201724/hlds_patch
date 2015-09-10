// FloodBlock.cpp : 定义 DLL 应用程序的导出函数。
//

#include "stdafx.h"
#include "moduleconfig.h"
#include "amxxmodule.h"
#include <vector>
#include "detours.h"
#include "CSigMngr.h"
#pragma comment(lib,"ws2_32.lib")
using namespace std;

#define SV_READCLIENTMSG "\x85\xC0\x74\xD6\x56\xFF\xD0\xEB\xCE"
#define SV_READCLIENTMSG_BYTES sizeof(SV_READCLIENTMSG)-1

DWORD blockThread;
typedef struct connect_list_s
{
	sockaddr_in sin;
	int first;
	//int block;
}connect_list_t;
typedef struct command_flood_s
{
	DWORD ip;
	DWORD delay;
	int count;
	bool block;
}command_flood_t;
vector <connect_list_t*> List;
vector <command_flood_t*> FloodList;
typedef int(WINAPI* fnrecvfrom)(
								SOCKET s,
								char* buf,
								int len,
								int flags,
struct sockaddr* from,
	int* fromlen
	);
fnrecvfrom precvfrom;

int WINAPI newrecvfrom(  
					   SOCKET s,
					   char* buf,
					   int len,
					   int flags,
struct sockaddr* from,
	int* fromlen)
{
	vector<connect_list_t*>::iterator iter;
	int result = precvfrom(s,buf,len,flags,from,fromlen);
	sockaddr_in* sockaddr_p = (sockaddr_in*)from;
	if(GetCurrentThreadId() == blockThread && result!=-1)
	{
		if(*(DWORD*)buf == -1)
		{
			if( buf[4] == 'c' &&
				buf[5] == 'o' && 
				buf[6] == 'n' && 
				buf[7] == 'n' &&
				buf[8] == 'e' &&
				buf[9] == 'c' &&
				buf[10] == 't') //connect
			{
				connect_list_t* m_list = new connect_list_t;
				m_list->first = 1;
				memcpy(&m_list->sin,sockaddr_p,sizeof(sockaddr_in));
				List.push_back(m_list);
			}
			return result;
		}
		for(size_t i=0;i<List.size();i++)
		{
			if(List[i]->sin.sin_addr.S_un.S_addr == sockaddr_p->sin_addr.S_un.S_addr)
			{
				if(List[i]->sin.sin_port == sockaddr_p->sin_port)
				{
					if(List[i]->first)
					{
						if(buf[0] != 1)
						{
							WSASetLastError(WSAEWOULDBLOCK);
							return -1;
						}
						List[i]->first = 0;
						for ( iter = List.begin(); iter != List.end();)
						{
							if((*iter)->sin.sin_addr.S_un.S_addr == sockaddr_p->sin_addr.S_un.S_addr)
							{
								if((*iter)->sin.sin_port == sockaddr_p->sin_port)
								{
									delete *iter;
									iter = List.erase(iter);
									return result;
								}
							}
							iter++;
						}
						break;
					}
				}

			}
		}
	}
	return result;
}
typedef char* (*fnget_command)();
fnget_command pget_command;
char* command;
char* get_command()
{
	command = pget_command();
	return command;
}
typedef void (*fnclc_stringcmd)(DWORD* client_t);
fnclc_stringcmd pclc_stringcmd;
//10 = ip
//13 = port(HIWORD)
void clc_stringcmd(DWORD* client_t)
{
	in_addr in;
	bool search_done=false;
	pclc_stringcmd(client_t);
	if(!memcmp(command,"sendres",7) || !memcmp(command,"new",3))
	{
		for(size_t i=0;i<FloodList.size();i++)
		{
			if(FloodList[i]->ip == client_t[10])
			{
				search_done = true;
				if(!FloodList[i]->block && (GetTickCount() - FloodList[i]->delay) < 1000)
				{
					FloodList[i]->count++;
					if(FloodList[i]->count > 6)
					{
						char BannedMsg[100];
						char szBannedCommand[100];
						in.S_un.S_addr = client_t[10];
						sprintf(szBannedCommand,"addip 0 %s;",inet_ntoa(in));
						sprintf(BannedMsg,"[Number Anti Crash]Player Flood Server BanPlayer:%s\n",inet_ntoa(in));
						g_engfuncs.pfnServerPrint(BannedMsg);
						g_engfuncs.pfnServerCommand(szBannedCommand);
						FloodList[i]->block = true;
						break;
					}
				}
				break;
			}
		}
		if(!search_done)
		{
			command_flood_t* m_item = new command_flood_t;
			m_item->delay = GetTickCount();
			m_item->ip = client_t[10];
			m_item->count = 1;
			m_item->block = false;
			FloodList.push_back(m_item);
		}
	}
	else
	{
		for(size_t i=0;i<FloodList.size();i++)
		{
			if(FloodList[i]->ip == client_t[10])
			{
				vector<command_flood_t*>::iterator iter;
				for ( iter = FloodList.begin(); iter != FloodList.end();)
				{
					if((*iter)->ip == client_t[10])
					{
						delete *iter;
						iter = FloodList.erase(iter);
						return;
					}
					iter++;
				}
				break;
			}
		}
	}
}
DWORD lastFrame=0;
void FN_StartFrame(void)
{
	vector<command_flood_t*>::iterator iter;
	DWORD m_frame = GetTickCount();
	if(!lastFrame)
	{
		lastFrame = GetTickCount();
	}
	if((m_frame - lastFrame) > 10000)
	{
		if(FloodList.size() > 0)
		{
			for ( iter = FloodList.begin(); iter != FloodList.end();)
			{
				if((m_frame - (*iter)->delay) > 1000)
				{
					delete *iter;
					iter = FloodList.erase(iter);
					continue;
				}
				iter++;
			}
		}
	}
	RETURN_META(MRES_IGNORED);
}
void OnMetaAttach()
{
	blockThread = GetCurrentThreadId();
	precvfrom = recvfrom;
	DetourTransactionBegin();
	DetourUpdateThread(GetCurrentThread());
	DetourAttach((void**)&precvfrom,newrecvfrom);
	DetourTransactionCommit();

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
}