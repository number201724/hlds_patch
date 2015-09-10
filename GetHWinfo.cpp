

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

// ���CPU��Ϣ
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
	// �õ�CPU�ṩ����Ϣ
	try
	{
		_asm
		{
			xor		eax, eax	// eax����
			cpuid				// ���CPU��Ϣ
			mov		dword ptr szVendor, ebx
			mov		dword ptr szVendor[+4], edx
			mov		dword ptr szVendor[+8], ecx
		}
		//strTemp.Format( "CPU�ṩ��: %s", szVendor );
		sprintf(strVendor,"%s",szVendor);
	}
	catch(...)
	{
		return false;
	}

	// �õ�CPU ID��32λ
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
		//strTemp.Format( "CPU ID��32λ: %08X", s1 );
		sprintf(strInfo1,"%08X", s1 );
	}
	catch(...)
	{
		return false;
	}

	// �õ�CPU ID�ĵ�64λ
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
		//strTemp.Format( "CPU ID��64λ: %08X-%08X", s1, s2 );
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

// ���Ӳ����Ϣ
bool CGetHWinfo::GetHDinfo( char *strSerial, char *strModelNum )
{
	sprintf(strSerial,"");
	sprintf(strModelNum,"");
	char serial[128],Modelunm[128];
	// �õ���ǰ����ϵͳ�汾
	OSVERSIONINFO OSVersionInfo;
	OSVersionInfo.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);
	if( !GetVersionEx( &OSVersionInfo ) )
		return false;

	// ���ݲ���ϵͳƽ̨ѡ��ͬ�Ķ�ȡ��ʽ
	if( OSVersionInfo.dwPlatformId == VER_PLATFORM_WIN32_NT )
	{
		// WinNT/2k/XP
		// �ȳ��Զ�ȡIDEӲ�����к�, ���ɹ��ٳ��Զ�ȡSCSIӲ�����к�
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

// �������MAC��ַ
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
// ��Ӳ����Ϣ����ת��Ϊ����ַ�
char* CGetHWinfo::ConvertToString( DWORD dwDiskData[256], int nFirstIndex, int nLastIndex )
{
	static char szResBuf[MAX_PATH];
	int nIndex = 0;
	int nPosition = 0;

	// Each integer has two characters stored in it backwards
	for( nIndex = nFirstIndex; nIndex <= nLastIndex; nIndex++ )
	{
		// ȡ��λ����һ���ַ�
		szResBuf[nPosition++] = (char)(dwDiskData[nIndex] / 256);
		// ȡ��λ���ڶ����ַ�
		szResBuf[nPosition++] = (char)(dwDiskData[nIndex] % 256);
	}

	// ��ӽ�����ʶ
	szResBuf[nPosition] = '\0';

	// �滻���ַ�
	for( nIndex = nPosition-1; nIndex > 0 && ' ' == szResBuf[nIndex]; nIndex-- )
		szResBuf[nIndex] = '\0';

	return szResBuf;
}

//-----------------------------
// NTƽ̨��, ���IDEӲ�����к�
bool CGetHWinfo::WinNTRead_IDEHD_Serial( char *strSerial, char *strModelNum )
{
sprintf(strSerial,"");
sprintf(strModelNum,"");

	bool bFlag = false;
	int nDrive = 0;
	char szDriveName[32];
	HANDLE hScsiDriveIOCTL = NULL;

	sprintf( szDriveName, "\\\\.\\PhysicalDrive%d", nDrive);
	// Windows NT/2000/XP�´����ļ���Ҫ����ԱȨ��
	hScsiDriveIOCTL = CreateFile( szDriveName, GENERIC_READ|GENERIC_WRITE
								, FILE_SHARE_READ|FILE_SHARE_WRITE, NULL
								, OPEN_EXISTING, 0, NULL );
	if( hScsiDriveIOCTL != INVALID_HANDLE_VALUE )
	{
		GETVERSIONOUTPARAMS VersionParams;
		ZeroMemory( &VersionParams, sizeof(VersionParams) );
		DWORD dwBytesReturned = 0;

		// �õ���������IO�������汾
		if( DeviceIoControl( hScsiDriveIOCTL, DFP_GET_VERSION
							, NULL, 0, &VersionParams, sizeof(VersionParams)
							, &dwBytesReturned, NULL ) )
		{
			if( VersionParams.bIDEDeviceMap > 0 )
			{
				BYTE bIDCmd = 0;	// IDE����ATAPIʶ������
				SENDCMDINPARAMS scip;

				// ����������ǹ���, ��������IDE_ATAPI_IDENTIFY
				// �����������IDE_ATA_IDENTIFY��ȡ��������Ϣ
				bIDCmd = (VersionParams.bIDEDeviceMap >> nDrive & 0x10)
							? IDE_ATAPI_IDENTIFY : IDE_ATA_IDENTIFY;
				ZeroMemory( &scip, sizeof(scip) );

				BYTE IdOutCmd[sizeof(SENDCMDOUTPARAMS) + 512 - 1];
				ZeroMemory( IdOutCmd, sizeof(IdOutCmd) );
				// ��ȡ��������Ϣ
				if( WinNTGetIDEInfo( hScsiDriveIOCTL, &scip
									, (PSENDCMDOUTPARAMS)&IdOutCmd
									, (BYTE)bIDCmd, (BYTE)nDrive
									, &dwBytesReturned ) )
				{
					DWORD dwDiskData[256];
					USHORT* pIDSector;	// ��Ӧ�ṹIDSECTOR

					pIDSector = (USHORT*)((SENDCMDOUTPARAMS*)IdOutCmd)->bBuffer;
					for( int i = 0; i < 256; i++ )
						dwDiskData[i] = pIDSector[i];

					// ���Ӳ�����к�
					char *d,*t;
					 d= ConvertToString( dwDiskData, 10, 19 );
					 sprintf(strSerial,"%s",d);
					// ���Ӳ���ͺ�
					 t = ConvertToString( dwDiskData, 27, 46 );
					sprintf(strModelNum,"%s",t);

					// ���˶�ȡӲ����Ϣ�ɹ�
					bFlag = true;
				}
			}
		}
		CloseHandle( hScsiDriveIOCTL );		// �رվ��
	}

	return bFlag;
}

// NTƽ̨��, ��ȡIDE�豸��Ϣ
bool CGetHWinfo::WinNTGetIDEInfo( HANDLE hPhysicalDriveIOCTL, PSENDCMDINPARAMS pSCIP
								, PSENDCMDOUTPARAMS pSCOP, BYTE bIDCmd
								, BYTE bDriveNum, PDWORD lpcbBytesReturned )
{
	// Ϊ��ȡ�豸��Ϣ׼������
	pSCIP->cBufferSize = IDENTIFY_BUFFER_SIZE;
	pSCIP->irDriveRegs.bFeaturesReg = 0;
	pSCIP->irDriveRegs.bSectorCountReg = 1;
	pSCIP->irDriveRegs.bSectorNumberReg = 1;
	pSCIP->irDriveRegs.bCylLowReg = 0;
	pSCIP->irDriveRegs.bCylHighReg = 0;

	// ����������λ��(���̺ʹ�������Ӧ��ֵ�ǲ�һ����)
	pSCIP->irDriveRegs.bDriveHeadReg = (bDriveNum & 1) ? 0xB0 : 0xA0;

	// ���ö�ȡ����, IDE��ATAPI�豸�Կ�
	pSCIP->irDriveRegs.bCommandReg = bIDCmd;
	pSCIP->bDriveNumber = bDriveNum;
	pSCIP->cBufferSize = IDENTIFY_BUFFER_SIZE;

	// ��ȡ��������Ϣ
	BOOL bRet = DeviceIoControl( hPhysicalDriveIOCTL
								, DFP_RCV_DRIVE_DATA
								, (LPVOID)pSCIP, sizeof(SENDCMDINPARAMS)-1
								, (LPVOID)pSCOP, sizeof(SENDCMDOUTPARAMS)+IDENTIFY_BUFFER_SIZE-1
								, lpcbBytesReturned, NULL );
	return bRet ? true : false;
}

//-----------------------------
// NTƽ̨��, ���SCSIӲ�����к�
bool CGetHWinfo::WinNTRead_SCSIHD_Serial( char * strSerial, char * strModelNum )
{
	/*strSerial.Empty();
	strModelNum.Empty();*/

	bool bFlag = false;
	int nDrive = 0;
	char szDriveName[32];
	HANDLE hScsiDriveIOCTL = NULL;

	sprintf( szDriveName, "\\\\.\\Scsi%d:", nDrive);
	// Windows NT/2000/XP�´����ļ���Ҫ����ԱȨ��
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

		// �õ���������IO�������汾
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

				// ���Ӳ�����к�
				strSerial = ConvertToString( dwDiskData, 10, 19 );
				// ���Ӳ���ͺ�
				strModelNum = ConvertToString( dwDiskData, 27, 46 );

				// ���˶�ȡӲ����Ϣ�ɹ�
				bFlag = true;
			}
		}
		CloseHandle( hScsiDriveIOCTL );		// �رվ��
	}

	return bFlag;
}

//-----------------------------
// 9xƽ̨��, ���Ӳ�����к�
bool CGetHWinfo::Win9xRead_HD_Serial( char * strSerial, char * strModelNum )
{
	/*strSerial.Empty();
	strModelNum.Empty()*/;

/*
	WORD wOutData[256];
	SetPriorityClass(GetCurrentProcess(), REALTIME_PRIORITY_CLASS);

	// �������ԣ����ֵ�һ�ε��ö���Drive >= 2ʱ����Ring0�����г��ִ��󣬵���������
	// ����N��N > 15���ε����������Ҳ���ԭ�򣺣������ò�����������һ�����ô�����
	// ���������ĳ��֡����ڴ�������ָ��ԭ��
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

		// ����Ring0
		ReadPhysicalDriveOnW9X_Ring0(true, dwBaseAddress, btMasterSlave,
			bIsIDEExist, IsDiskExist, wOutData);
	}

	// ��ʼ��ȡ
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

		// ����Ring0
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

			// ȡϵ�к�
			ZeroMemory(szSerialNumber, sizeof(szSerialNumber));
			strcpy(szSerialNumber, ConvertToString(dwDiskData, 10, 19));

			// ȡģ�ͺ�
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

// ����Ring0��ȡӲ����Ϣ
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
			// ������ִ���������
			JMP EnterRing0

				// �������
				// �ȴ�IDE�豸ֱ���䲻ΪæΪֹ
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

				// ��ʱ��ֱ���˳�
Timeout:
			JMP LeaveRing0
DriveReady:
			RET
				ENDP // End of WaitWhileBusy Procedure

				// �������̺ʹ��̱�־
				SelectDevice proc

				MOV DX, dwBaseAddress
				ADD DX, 6
				MOV AL, btMasterSlave

				out DX, AL
				RET

				ENDP // End of SelectDevice Procedure

				// ��IDE�豸���ʹ�ȡָ��
				SendCmd proc

				MOV DX, dwBaseAddress
				ADD DX, 7
				MOV AL, BL // BL�������̱�ʶ���ڹ���������
				out DX, AL
				RET
				ENDP // End of SendCmd Procedure

				// Ring0����
Ring0Proc:
			PUSHAD
				// ��ѯIDE�豸�Ƿ����
				MOV DX, dwBaseAddress
				ADD DX, 7
				in AL,DX

				// ��AL��ֵ��0xFF����0x7Fʱ��IDE�豸�����ڣ���ʱ��ֱ�ӷ���
				CMP AL,0xFF
				JZ LeaveRing0
				CMP AL, 0x7F
				JZ LeaveRing0

				// ����IDE�豸���ڱ�־
				MOV btIsIDEExist, 1

				// ��ѯIDE�豸�ϵ��������Ƿ���ڣ���IDE����������ϣ�����ȴ��һ����Ӳ�̲������棩
				CALL WaitWhileBusy
				CALL SelectDevice

				// ����ǵ�һ�ε��ã���ֱ�ӷ��أ�����ִ���������ʱ���������
				CMP btIsFirst, 1
				JZ LeaveRing0

				// ��һ�ε���ʱ�����ִ���������ᵼ��������Why������
				CALL WaitWhileBusy

				// AL��ֵ����cBit06ʱ����������������ֱ�ӷ���
				TEST AL, btBit06
				JZ LeaveRing0

				// �������������ڱ�־
				MOV btIsDiskExist, 1

				// ���ʹ�ȡ�˿�����
				// �޷���NT/2000/XP��������ͨ����ѯVERSION��ֵ�õ������������ͣ�
				// ����ֻ��һ��һ���ز��ԣ��������ATA�豸���ٳ���ʹ��ATAPI�豸����
				CALL WaitWhileBusy
				CALL SelectDevice // ���������̱�ʶ
				MOV BL, btAtaCmd // ���Ͷ�ȡ����
				CALL SendCmd
				CALL WaitWhileBusy

				// ����Ƿ����
				MOV DX, dwBaseAddress
				ADD DX, 7

				in AL, DX

				TEST AL, btBit00
				JZ RetrieveInfo // û�д���ʱ�������

				// ����������һ������ʹ��ATAPI�豸����
				CALL WaitWhileBusy
				CALL SelectDevice
				MOV BL, btAtapiCmd
				CALL SendCmd
				CALL WaitWhileBusy

				// ����Ƿ񻹳���
				MOV DX, dwBaseAddress
				ADD DX, 7
				in AL, DX
				TEST AL, btBit00
				JZ RetrieveInfo // û�д���ʱ�������
				JMP LeaveRing0 // ������ǳ���ֱ�ӷ���

				// ��ȡ����
RetrieveInfo:

			LEA EDI, wOutDataBuf
				MOV ECX, 256
				MOV DX, dwBaseAddress
				CLD

				REP INSW

				// �˳�Ring0����
LeaveRing0:

			POPAD
				IRETD

				// ����Ring0����
EnterRing0:

			// �޸��ж���
			SIDT FWORD PTR btIDTR1
				MOV EAX, DWORD PTR btIDTR1 + 02h
				ADD EAX, nHookExceptionNo * 08h + 04h
				CLI

				// ����ԭ�쳣�����������
				MOV ECX, DWORD PTR [EAX]
				MOV CX, WORD PTR [EAX-04h]
				MOV dwOldExceptionHook, ECX

					// ָ�������
					LEA EBX, Ring0Proc
					MOV WORD PTR [EAX-04h],BX
					SHR EBX, 10h
					MOV WORD PTR[EAX+02h], BX

					// ����Ring0����
					INT nHookExceptionNo

					// ��ԭ���
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
