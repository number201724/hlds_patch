

#include <Windows.h>
#include "GetHWinfo.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
//#include <RpcDce.h>
#include <Rpc.h>

CGetHWinfo hwinfo;
CGetHWinfo::CGetHWinfo(void)
{
}

CGetHWinfo::~CGetHWinfo(void)
{
}

// 获得CPU信息
bool CGetHWinfo::GetCPUinfo( char *strVendor, char *strInfo1,char *strInfo2 )
{
	_asm
	{
		push	eax
		push	ebx
		push	ecx
		push	edx
	}

	unsigned char szVendor[16];
	ZeroMemory( szVendor, sizeof(szVendor) );
	// 得到CPU提供商信息
	try
	{
		_asm
		{
			xor		eax, eax	// eax清零
			cpuid				// 获得CPU信息
			mov		dword ptr szVendor, ebx
			mov		dword ptr szVendor[+4], edx
			mov		dword ptr szVendor[+8], ecx
		}
		//strTemp.Format( "CPU提供商: %s", szVendor );
		sprintf(strVendor,"%s",szVendor);
	}
	catch(...)
	{
		return false;
	}

	// 得到CPU ID高32位
	DWORD s1;
	try
	{
		_asm
		{
			mov		eax, 01h
			xor		edx, edx
			cpuid
			mov		s1, eax
		}
		//strTemp.Format( "CPU ID高32位: %08X", s1 );
		sprintf(strInfo1,"%08X", s1 );
	}
	catch(...)
	{
		return false;
	}

	// 得到CPU ID的低64位
	try
	{
		_asm
		{
			mov		eax, 03h
			xor		ebx, ebx
			xor		ecx, ecx
			cpuid
			mov		s1, edx
			//mov		s2, ecx
		}
		//strTemp.Format( "CPU ID低64位: %08X-%08X", s1, s2 );
		//strInfo2.Format( "%08X-%08X", s1, s2 );
		sprintf(strInfo2,"%08X", s1 );
	}
	catch(...)
	{
		return false;
	}

	_asm
	{
		pop		eax
		pop		ebx
		pop		ecx
		pop		edx
	}

	return true;
}

// 获得硬盘信息
bool CGetHWinfo::GetHDinfo( char *strSerial, char *strModelNum )
{
	sprintf(strSerial,"");
	sprintf(strModelNum,"");
	char serial[128],Modelunm[128];
	// 得到当前操作系统版本
	OSVERSIONINFO OSVersionInfo;
	OSVersionInfo.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);
	if( !GetVersionEx( &OSVersionInfo ) )
		return false;

	// 根据操作系统平台选择不同的读取方式
	if( OSVersionInfo.dwPlatformId == VER_PLATFORM_WIN32_NT )
	{
		// WinNT/2k/XP
		// 先尝试读取IDE硬盘序列号, 不成功再尝试读取SCSI硬盘序列号
		if( !WinNTRead_IDEHD_Serial( serial, Modelunm ) )
			if( !WinNTRead_SCSIHD_Serial( strSerial, strModelNum ) )
				return false;
	}
	else
	{
		// Win9x/ME
		if( !Win9xRead_HD_Serial( strSerial, strModelNum ) )
			return false;
	}
	sprintf(strSerial,"%s",serial);
	sprintf(strModelNum,"%s",Modelunm);
	//strSerial.Trim();
	//strModelNum.Trim();

	return true;
}

// 获得网卡MAC地址
bool CGetHWinfo::GetMACinfo( char *strMAC )
{
	/*strMAC.Empty();*/
   sprintf(strMAC,"");

	UUID uid;
	if( RPC_S_OK != UuidCreateSequential( &uid ) )
		return false;

	char szMac[6][10];
	ZeroMemory( szMac, sizeof(szMac) );
	_itoa( uid.Data4[2], szMac[0], 16 );
	_itoa( uid.Data4[3], szMac[1], 16 );
	_itoa( uid.Data4[4], szMac[2], 16 );
	_itoa( uid.Data4[5], szMac[3], 16 );
	_itoa( uid.Data4[6], szMac[4], 16 );
	_itoa( uid.Data4[7], szMac[5], 16 );

	sprintf(strMAC,"%02s%02s%02s%02s%02s%02s"
				, szMac[0], szMac[1], szMac[2]
				, szMac[3], szMac[4], szMac[5] );
	/*strMAC.MakeUpper();*/

	return true;
}


//-----------------------------
// 把硬盘信息序列转换为输出字符
char* CGetHWinfo::ConvertToString( DWORD dwDiskData[256], int nFirstIndex, int nLastIndex )
{
	static char szResBuf[MAX_PATH];
	int nIndex = 0;
	int nPosition = 0;

	// Each integer has two characters stored in it backwards
	for( nIndex = nFirstIndex; nIndex <= nLastIndex; nIndex++ )
	{
		// 取高位做第一个字符
		szResBuf[nPosition++] = (char)(dwDiskData[nIndex] / 256);
		// 取低位做第二个字符
		szResBuf[nPosition++] = (char)(dwDiskData[nIndex] % 256);
	}

	// 添加结束标识
	szResBuf[nPosition] = '\0';

	// 替换空字符
	for( nIndex = nPosition-1; nIndex > 0 && ' ' == szResBuf[nIndex]; nIndex-- )
		szResBuf[nIndex] = '\0';

	return szResBuf;
}

//-----------------------------
// NT平台下, 获得IDE硬盘序列号
bool CGetHWinfo::WinNTRead_IDEHD_Serial( char *strSerial, char *strModelNum )
{
sprintf(strSerial,"");
sprintf(strModelNum,"");

	bool bFlag = false;
	int nDrive = 0;
	char szDriveName[32];
	HANDLE hScsiDriveIOCTL = NULL;

	sprintf( szDriveName, "\\\\.\\PhysicalDrive%d", nDrive);
	// Windows NT/2000/XP下创建文件需要管理员权限
	hScsiDriveIOCTL = CreateFile( szDriveName, GENERIC_READ|GENERIC_WRITE
								, FILE_SHARE_READ|FILE_SHARE_WRITE, NULL
								, OPEN_EXISTING, 0, NULL );
	if( hScsiDriveIOCTL != INVALID_HANDLE_VALUE )
	{
		GETVERSIONOUTPARAMS VersionParams;
		ZeroMemory( &VersionParams, sizeof(VersionParams) );
		DWORD dwBytesReturned = 0;

		// 得到驱动器的IO控制器版本
		if( DeviceIoControl( hScsiDriveIOCTL, DFP_GET_VERSION
							, NULL, 0, &VersionParams, sizeof(VersionParams)
							, &dwBytesReturned, NULL ) )
		{
			if( VersionParams.bIDEDeviceMap > 0 )
			{
				BYTE bIDCmd = 0;	// IDE或者ATAPI识别命令
				SENDCMDINPARAMS scip;

				// 如果驱动器是光驱, 采用命令IDE_ATAPI_IDENTIFY
				// 否则采用命令IDE_ATA_IDENTIFY读取驱动器信息
				bIDCmd = (VersionParams.bIDEDeviceMap >> nDrive & 0x10)
							? IDE_ATAPI_IDENTIFY : IDE_ATA_IDENTIFY;
				ZeroMemory( &scip, sizeof(scip) );

				BYTE IdOutCmd[sizeof(SENDCMDOUTPARAMS) + 512 - 1];
				ZeroMemory( IdOutCmd, sizeof(IdOutCmd) );
				// 获取驱动器信息
				if( WinNTGetIDEInfo( hScsiDriveIOCTL, &scip
									, (PSENDCMDOUTPARAMS)&IdOutCmd
									, (BYTE)bIDCmd, (BYTE)nDrive
									, &dwBytesReturned ) )
				{
					DWORD dwDiskData[256];
					USHORT* pIDSector;	// 对应结构IDSECTOR

					pIDSector = (USHORT*)((SENDCMDOUTPARAMS*)IdOutCmd)->bBuffer;
					for( int i = 0; i < 256; i++ )
						dwDiskData[i] = pIDSector[i];

					// 获得硬盘序列号
					char *d,*t;
					 d= ConvertToString( dwDiskData, 10, 19 );
					 sprintf(strSerial,"%s",d);
					// 获得硬盘型号
					 t = ConvertToString( dwDiskData, 27, 46 );
					sprintf(strModelNum,"%s",t);

					// 至此读取硬盘信息成功
					bFlag = true;
				}
			}
		}
		CloseHandle( hScsiDriveIOCTL );		// 关闭句柄
	}

	return bFlag;
}

// NT平台下, 读取IDE设备信息
bool CGetHWinfo::WinNTGetIDEInfo( HANDLE hPhysicalDriveIOCTL, PSENDCMDINPARAMS pSCIP
								, PSENDCMDOUTPARAMS pSCOP, BYTE bIDCmd
								, BYTE bDriveNum, PDWORD lpcbBytesReturned )
{
	// 为读取设备信息准备参数
	pSCIP->cBufferSize = IDENTIFY_BUFFER_SIZE;
	pSCIP->irDriveRegs.bFeaturesReg = 0;
	pSCIP->irDriveRegs.bSectorCountReg = 1;
	pSCIP->irDriveRegs.bSectorNumberReg = 1;
	pSCIP->irDriveRegs.bCylLowReg = 0;
	pSCIP->irDriveRegs.bCylHighReg = 0;

	// 计算驱动器位置(主盘和从盘所对应的值是不一样的)
	pSCIP->irDriveRegs.bDriveHeadReg = (bDriveNum & 1) ? 0xB0 : 0xA0;

	// 设置读取命令, IDE或ATAPI设备皆可
	pSCIP->irDriveRegs.bCommandReg = bIDCmd;
	pSCIP->bDriveNumber = bDriveNum;
	pSCIP->cBufferSize = IDENTIFY_BUFFER_SIZE;

	// 读取驱动器信息
	BOOL bRet = DeviceIoControl( hPhysicalDriveIOCTL
								, DFP_RCV_DRIVE_DATA
								, (LPVOID)pSCIP, sizeof(SENDCMDINPARAMS)-1
								, (LPVOID)pSCOP, sizeof(SENDCMDOUTPARAMS)+IDENTIFY_BUFFER_SIZE-1
								, lpcbBytesReturned, NULL );
	return bRet ? true : false;
}

//-----------------------------
// NT平台下, 获得SCSI硬盘序列号
bool CGetHWinfo::WinNTRead_SCSIHD_Serial( char * strSerial, char * strModelNum )
{
	/*strSerial.Empty();
	strModelNum.Empty();*/

	bool bFlag = false;
	int nDrive = 0;
	char szDriveName[32];
	HANDLE hScsiDriveIOCTL = NULL;

	sprintf( szDriveName, "\\\\.\\Scsi%d:", nDrive);
	// Windows NT/2000/XP下创建文件需要管理员权限
	hScsiDriveIOCTL = CreateFile( szDriveName, GENERIC_READ|GENERIC_WRITE
								, FILE_SHARE_READ|FILE_SHARE_WRITE, NULL
								, OPEN_EXISTING, 0, NULL );
	if( hScsiDriveIOCTL != INVALID_HANDLE_VALUE )
	{
		char szBuffer[sizeof(SRB_IO_CONTROL) + SENDIDLENGTH ];
		SRB_IO_CONTROL* pSic = (SRB_IO_CONTROL*)szBuffer;
		SENDCMDINPARAMS* pScip = (SENDCMDINPARAMS*)(szBuffer + sizeof(SRB_IO_CONTROL));

		ZeroMemory( szBuffer, sizeof(szBuffer) );
		pSic->HeaderLength = sizeof(SRB_IO_CONTROL);
		pSic->Timeout = 10000;
		pSic->Length = SENDIDLENGTH;
		pSic->ControlCode = IOCTL_SCSI_MINIPORT_IDENTIFY;
		strncpy( (char*)pSic->Signature, "SCSIDISK", 8 );

		pScip->irDriveRegs.bCommandReg = IDE_ATA_IDENTIFY;
		pScip->bDriveNumber = nDrive;

		// 得到驱动器的IO控制器版本
		DWORD dwBytesReturned = 0;
		if( DeviceIoControl( hScsiDriveIOCTL, IOCTL_SCSI_MINIPORT
							, szBuffer, sizeof(SRB_IO_CONTROL)+sizeof(SENDCMDINPARAMS)-1
							, szBuffer, sizeof(SRB_IO_CONTROL)+SENDIDLENGTH
							, &dwBytesReturned, NULL ) )
		{
			SENDCMDOUTPARAMS* pScop = (SENDCMDOUTPARAMS*)(szBuffer + sizeof(SRB_IO_CONTROL));
			IDSECTOR* pId = (IDSECTOR*)pScop->bBuffer;
			if( pId->sModelNumber[0] )
			{
				DWORD dwDiskData[256];
				USHORT* pIdSector = (USHORT*)pId;
				for( int i = 0; i < 256; i++ )
					dwDiskData[i] = pIdSector[i];

				// 获得硬盘序列号
				strSerial = ConvertToString( dwDiskData, 10, 19 );
				// 获得硬盘型号
				strModelNum = ConvertToString( dwDiskData, 27, 46 );

				// 至此读取硬盘信息成功
				bFlag = true;
			}
		}
		CloseHandle( hScsiDriveIOCTL );		// 关闭句柄
	}

	return bFlag;
}

//-----------------------------
// 9x平台下, 获得硬盘序列号
bool CGetHWinfo::Win9xRead_HD_Serial( char * strSerial, char * strModelNum )
{
	/*strSerial.Empty();
	strModelNum.Empty()*/;

/*
	WORD wOutData[256];
	SetPriorityClass(GetCurrentProcess(), REALTIME_PRIORITY_CLASS);

	// 经过测试，发现第一次调用而且Drive >= 2时会在Ring0代码中出现错误，导致蓝屏。
	// 经过N（N > 15）次的蓝屏后仍找不到原因：（，不得不在这里增加一段无用代码以
	// 避免蓝屏的出现。（期待高人能指出原因）
	for(int nDrive = 0; nDrive < 8; nDrive++)
	{
		WORD dwBaseAddress;
		BYTE btMasterSlave; // Master Or Slave
		bool bIsIDEExist;
		bool IsDiskExist;

		switch(nDrive / 2)
		{
		case 0: dwBaseAddress = 0x01F0; break;
		case 1: dwBaseAddress = 0x0170; break;
		case 2: dwBaseAddress = 0x01E8; break;
		case 3: dwBaseAddress = 0x0168; break;
		}

		btMasterSlave = (BYTE)(((nDrive % 2) == 0) ? 0xA0 : 0xB0);

		// 进入Ring0
		ReadPhysicalDriveOnW9X_Ring0(true, dwBaseAddress, btMasterSlave,
			bIsIDEExist, IsDiskExist, wOutData);
	}

	// 开始读取
	for(int nDrive = 0; nDrive < 8; nDrive++)
	{
		WORD dwBaseAddress;
		BYTE btMasterSlave; // Master Or Slave
		bool bIsIDEExist;
		bool bIsDiskExist;
		switch(nDrive / 2)
		{
		case 0: dwBaseAddress = 0x01F0; break;
		case 1: dwBaseAddress = 0x0170; break;
		case 2: dwBaseAddress = 0x01E8; break;
		case 3: dwBaseAddress = 0x0168; break;
		}

		btMasterSlave = (BYTE)(((nDrive % 2) == 0) ? 0xA0 : 0xB0);

		// 进入Ring0
		bIsIDEExist = false;
		bIsDiskExist = false;
		ZeroMemory(wOutData, sizeof(wOutData));

		ReadPhysicalDriveOnW9X_Ring0(false, dwBaseAddress, btMasterSlave,
			bIsIDEExist, bIsDiskExist, wOutData);

		if(bIsIDEExist && bIsDiskExist)
		{
			DWORD dwDiskData[256];
			char szSerialNumber[21];
			char szModelNumber[41];

			for(int k=0; k < 256; k++)
				dwDiskData[k] = wOutData[k];

			// 取系列号
			ZeroMemory(szSerialNumber, sizeof(szSerialNumber));
			strcpy(szSerialNumber, ConvertToString(dwDiskData, 10, 19));

			// 取模型号
			ZeroMemory(szModelNumber, sizeof(szModelNumber));
			strcpy(szModelNumber, ConvertToString(dwDiskData, 27, 46));

			pSerList->Add(szSerialNumber);
			pModeList->Add(szModelNumber);
		}
	}
	SetPriorityClass(GetCurrentProcess(), NORMAL_PRIORITY_CLASS);
*/

	return true;
}

// 进入Ring0读取硬盘信息
// dwBaseAddress = IDE(0,1,2,3) : 1F0h, 170h, 1E8h, 168h
// cbMasterSlave = Master(0xA0) Or Slave(0xB0)
bool CGetHWinfo::Win9xRead_HD_InRing0( bool bFirst, WORD wBaseAddress
										, BYTE cbMasterSlave, bool& bIDEExist
										, bool& bDiskExist, WORD* OutData )
{
/*
	void __fastcall ReadPhysicalDriveOnW9X_Ring0(bool bIsFirst, WORD dwBaseAddress,
		BYTE btMasterSlave, bool &bIsIDEExist, bool &bIsDiskExist, WORD *pOutData)
	{
		BYTE btIDTR1[6];
		DWORD dwOldExceptionHook;
		const int nHookExceptionNo = 5;

		BYTE btIsIDEExist = 0;
		BYTE btIsDiskExist = 0;
		WORD wOutDataBuf[256];

		BYTE btIsFirst = (BYTE)bIsFirst;

		const BYTE btBit00 = 0x01;
		// const BYTE btBit02 = 0x04;
		const BYTE btBit06 = 0x40;
		const BYTE btBit07 = 0x80;
		// const BYTE btERR = btBit00;
		const BYTE btBusy = btBit07;
		const BYTE btAtaCmd = 0xEC;
		const BYTE btAtapiCmd = 0xA1;

		__asm
		{
			// 必须先执行这条语句
			JMP EnterRing0

				// 定义过程
				// 等待IDE设备直到其不为忙为止
				WaitWhileBusy proc

				MOV EBX, 100000
				MOV DX, dwBaseAddress
				ADD DX, 7

LoopWhileBusy:

			DEC EBX
				CMP EBX, 0
				JZ Timeout
				in AL, DX
				TEST AL, btBusy
				JNZ LoopWhileBusy
				JMP DriveReady

				// 超时，直接退出
Timeout:
			JMP LeaveRing0
DriveReady:
			RET
				ENDP // End of WaitWhileBusy Procedure

				// 设置主盘和从盘标志
				SelectDevice proc

				MOV DX, dwBaseAddress
				ADD DX, 6
				MOV AL, btMasterSlave

				out DX, AL
				RET

				ENDP // End of SelectDevice Procedure

				// 向IDE设备发送存取指令
				SendCmd proc

				MOV DX, dwBaseAddress
				ADD DX, 7
				MOV AL, BL // BL是主从盘标识，在过程外设置
				out DX, AL
				RET
				ENDP // End of SendCmd Procedure

				// Ring0代码
Ring0Proc:
			PUSHAD
				// 查询IDE设备是否存在
				MOV DX, dwBaseAddress
				ADD DX, 7
				in AL,DX

				// 当AL的值是0xFF或者0x7F时，IDE设备不存在，这时候直接返回
				CMP AL,0xFF
				JZ LeaveRing0
				CMP AL, 0x7F
				JZ LeaveRing0

				// 设置IDE设备存在标志
				MOV btIsIDEExist, 1

				// 查询IDE设备上的驱动器是否存在（有IDE插槽在主板上，但是却不一定有硬盘插在上面）
				CALL WaitWhileBusy
				CALL SelectDevice

				// 如果是第一次调用，则直接返回，否则执行下行语句时会出现蓝屏
				CMP btIsFirst, 1
				JZ LeaveRing0

				// 第一次调用时，如果执行这行语句会导致蓝屏，Why？？？
				CALL WaitWhileBusy

				// AL的值等于cBit06时，不存在驱动器，直接返回
				TEST AL, btBit06
				JZ LeaveRing0

				// 设置驱动器存在标志
				MOV btIsDiskExist, 1

				// 发送存取端口命令
				// 无法像NT/2000/XP那样可以通过查询VERSION的值得到驱动器的类型，
				// 所以只能一步一步地测试，如果不是ATA设备，再尝试使用ATAPI设备命令
				CALL WaitWhileBusy
				CALL SelectDevice // 设置主从盘标识
				MOV BL, btAtaCmd // 发送读取命令
				CALL SendCmd
				CALL WaitWhileBusy

				// 检查是否出错
				MOV DX, dwBaseAddress
				ADD DX, 7

				in AL, DX

				TEST AL, btBit00
				JZ RetrieveInfo // 没有错误时则读数据

				// 如果出错，则进一步尝试使用ATAPI设备命令
				CALL WaitWhileBusy
				CALL SelectDevice
				MOV BL, btAtapiCmd
				CALL SendCmd
				CALL WaitWhileBusy

				// 检查是否还出错
				MOV DX, dwBaseAddress
				ADD DX, 7
				in AL, DX
				TEST AL, btBit00
				JZ RetrieveInfo // 没有错误时则读数据
				JMP LeaveRing0 // 如果还是出错，直接返回

				// 读取数据
RetrieveInfo:

			LEA EDI, wOutDataBuf
				MOV ECX, 256
				MOV DX, dwBaseAddress
				CLD

				REP INSW

				// 退出Ring0代码
LeaveRing0:

			POPAD
				IRETD

				// 激活Ring0代码
EnterRing0:

			// 修改中断门
			SIDT FWORD PTR btIDTR1
				MOV EAX, DWORD PTR btIDTR1 + 02h
				ADD EAX, nHookExceptionNo * 08h + 04h
				CLI

				// 保存原异常处理例程入口
				MOV ECX, DWORD PTR [EAX]
				MOV CX, WORD PTR [EAX-04h]
				MOV dwOldExceptionHook, ECX

					// 指定新入口
					LEA EBX, Ring0Proc
					MOV WORD PTR [EAX-04h],BX
					SHR EBX, 10h
					MOV WORD PTR[EAX+02h], BX

					// 激活Ring0代码
					INT nHookExceptionNo

					// 复原入口
					MOV ECX,dwOldExceptionHook
					MOV WORD PTR[EAX-04h], CX
					SHR ECX,10h
					MOV WORD PTR[EAX+02h], CX
					STI
		}
		if(!bIsFirst)
		{
			bIsIDEExist = (bool)btIsIDEExist;
			bIsDiskExist = (bool)btIsDiskExist;
			CopyMemory(pOutData, wOutDataBuf, sizeof(wOutDataBuf));
		}
	}
*/

	return true;
}
