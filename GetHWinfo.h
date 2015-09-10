
#pragma once

#ifndef GET_HW_INFO
#define GET_HW_INFO
// �������ԡ���Win9x/NT�»�ȡӲ���������кš�http://www.05815.com/article.asp?id=165


//#include "RPCdce.h"
#include "winioctl.h"
#pragma comment( lib, "Rpcrt4.lib" )

#pragma warning(disable:4996)

//#define CTL_CODE( DeviceType, Function, Method, Access ) (                 \
//    ((DeviceType) << 16) | ((Access) << 14) | ((Function) << 2) | (Method) \
//)
//
//
//
//#define SMART_GET_VERSION               CTL_CODE(0x00000007, 0x0020, 0, 0x0001)
//#define SMART_SEND_DRIVE_COMMAND        CTL_CODE(0x00000007, 0x0021, 0, 0x0001 | 0x0002)
//#define SMART_RCV_DRIVE_DATA            CTL_CODE(0x00000007, 0x0022, 0, 0x0001 | 0x0002)
//
//
//typedef struct _DRIVERSTATUS {
//        BYTE     bDriverError;           // Error code from driver,
//                                                                // or 0 if no error.
//        BYTE     bIDEError;                      // Contents of IDE Error register.
//                                                                // Only valid when bDriverError
//                                                                // is SMART_IDE_ERROR.
//        BYTE     bReserved[2];           // Reserved for future expansion.
//        DWORD   dwReserved[2];          // Reserved for future expansion.
//} DRIVERSTATUS, *PDRIVERSTATUS, *LPDRIVERSTATUS;
//
////
//typedef struct _SENDCMDOUTPARAMS {
//        DWORD                   cBufferSize;            // Size of bBuffer in bytes
//        DRIVERSTATUS            DriverStatus;           // Driver status structure.
//        BYTE                    bBuffer[1];             // Buffer of arbitrary length in which to store the data read from the                                                                                  // drive.
//} SENDCMDOUTPARAMS, *PSENDCMDOUTPARAMS, *LPSENDCMDOUTPARAMS;
//typedef struct _IDEREGS {
//        BYTE     bFeaturesReg;           // Used for specifying SMART "commands".
//        BYTE     bSectorCountReg;        // IDE sector count register
//        BYTE     bSectorNumberReg;       // IDE sector number register
//        BYTE     bCylLowReg;             // IDE low order cylinder value
//        BYTE     bCylHighReg;            // IDE high order cylinder value
//        BYTE     bDriveHeadReg;          // IDE drive/head register
//        BYTE     bCommandReg;            // Actual IDE command.
//        BYTE     bReserved;                      // reserved for future use.  Must be zero.
//} IDEREGS, *PIDEREGS, *LPIDEREGS;
//
//typedef struct _SENDCMDINPARAMS {
//        DWORD   cBufferSize;            // Buffer size in bytes
//        IDEREGS irDriveRegs;            // Structure with drive register values.
//        BYTE     bDriveNumber;           // Physical drive number to send
//                                                                // command to (0,1,2,3).
//        BYTE     bReserved[3];           // Reserved for future expansion.
//        DWORD   dwReserved[4];          // For future use.
//        BYTE     bBuffer[1];                     // Input buffer.
//} SENDCMDINPARAMS, *PSENDCMDINPARAMS, *LPSENDCMDINPARAMS;
//
//typedef struct _GETVERSIONINPARAMS {
//        BYTE     bVersion;               // Binary driver version.
//        BYTE     bRevision;              // Binary driver revision.
//        BYTE     bReserved;              // Not used.
//        BYTE     bIDEDeviceMap;          // Bit map of IDE devices.
//        DWORD   fCapabilities;          // Bit mask of driver capabilities.
//        DWORD   dwReserved[4];          // For future use.
//} GETVERSIONINPARAMS, *PGETVERSIONINPARAMS, *LPGETVERSIONINPARAMS;
//#define IDENTIFY_BUFFER_SIZE 512

// IDE NT/2000/XPר�ñ���
#define	GETVERSIONOUTPARAMS		GETVERSIONINPARAMS
#define	DFP_GET_VERSION			SMART_GET_VERSION
#define	DFP_SEND_DRIVE_COMMAND	SMART_SEND_DRIVE_COMMAND
#define	DFP_RCV_DRIVE_DATA		SMART_RCV_DRIVE_DATA



const WORD IDE_ATAPI_IDENTIFY	= 0xA1;		// ��ȡATAPI�豸������
const WORD IDE_ATA_IDENTIFY		= 0xEC;		// ��ȡATA�豸������
const int MAX_IDE_DRIVES		= 4;

// SCSIר�ñ���
const DWORD FILE_DEVICE_SCSI	= 0x0000001B;
const DWORD IOCTL_SCSI_MINIPORT_IDENTIFY	= ((FILE_DEVICE_SCSI << 16) + 0x0501);
const DWORD IOCTL_SCSI_MINIPORT	= 0x0004D008;	// see NTDDSCSI.H for definition
const DWORD SENDIDLENGTH		= sizeof(SENDCMDOUTPARAMS) + IDENTIFY_BUFFER_SIZE;

typedef struct _SRB_IO_CONTROL
{
	ULONG HeaderLength;
	UCHAR Signature[8];
	ULONG Timeout;
	ULONG ControlCode;
	ULONG ReturnCode;
	ULONG Length;
} SRB_IO_CONTROL, *PSRB_IO_CONTROL;

typedef struct _IDSECTOR
{
	USHORT  wGenConfig;
	USHORT  wNumCyls;
	USHORT  wReserved;
	USHORT  wNumHeads;
	USHORT  wBytesPerTrack;
	USHORT  wBytesPerSector;
	USHORT  wSectorsPerTrack;
	USHORT  wVendorUnique[3];
	CHAR    sSerialNumber[20];
	USHORT  wBufferType;
	USHORT  wBufferSize;
	USHORT  wECCSize;
	CHAR    sFirmwareRev[8];
	CHAR    sModelNumber[40];
	USHORT  wMoreVendorUnique;
	USHORT  wDoubleWordIO;
	USHORT  wCapabilities;
	USHORT  wReserved1;
	USHORT  wPIOTiming;
	USHORT  wDMATiming;
	USHORT  wBS;
	USHORT  wNumCurrentCyls;
	USHORT  wNumCurrentHeads;
	USHORT  wNumCurrentSectorsPerTrack;
	ULONG   ulCurrentSectorCapacity;
	USHORT  wMultSectorStuff;
	ULONG   ulTotalAddressableSectors;
	USHORT  wSingleWordDMA;
	USHORT  wMultiWordDMA;
	BYTE    bReserved[128];
} IDSECTOR, *PIDSECTOR;


//-------------------------------------
// CGetHWinfo: ���Ӳ����Ϣ�Ĺ�����
//-------------------------------------
class CGetHWinfo
{
public:
	CGetHWinfo(void);
	~CGetHWinfo(void);

	// ���CPU��Ϣ
	bool GetCPUinfo( char *strVendor, char *strInfo1,char *strInfo2 );
	// ���Ӳ����Ϣ
	bool GetHDinfo( char *strSerial, char *strModelNum );
	// �������MAC��ַ
	bool GetMACinfo( char *strMAC );


protected:
	// ��Ӳ����Ϣ����ת��Ϊ����ַ�
	char* ConvertToString( DWORD dwDiskData[256], int nFirstIndex, int nLastIndex );

	//-----------------------------
	// NTƽ̨��, ���IDEӲ�����к�
	bool WinNTRead_IDEHD_Serial( char * strSerial, char * strModelNum );
	// NTƽ̨��, ��ȡIDE�豸��Ϣ
	bool WinNTGetIDEInfo( HANDLE hPhysicalDriveIOCTL, PSENDCMDINPARAMS pSCIP
						, PSENDCMDOUTPARAMS pSCOP, BYTE bIDCmd
						, BYTE bDriveNum, PDWORD lpcbBytesReturned );
	//-----------------------------
	// NTƽ̨��, ���SCSIӲ�����к�
	bool WinNTRead_SCSIHD_Serial( char * strSerial, char * strModelNum );

	//-----------------------------
	// 9xƽ̨��, ���Ӳ�����к�
	bool Win9xRead_HD_Serial( char *strSerial, char * strModelNum );
	// ����Ring0��ȡӲ����Ϣ
	bool Win9xRead_HD_InRing0( bool bFirst, WORD wBaseAddress
							, BYTE cbMos, bool& bIDEExist
							, bool& bDiskExist, WORD* OutData );
};


extern CGetHWinfo hwinfo;

#endif