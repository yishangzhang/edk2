/*
 * @Author: yishangzhang 
 * @Date: 2023-11-30 12:10:24 
 * @Last Modified by:   yishangzhang 
 * @Last Modified time: 2023-11-30 12:10:24 
 */

#include <Library/BaseMemoryLib.h>
#include <Library/DebugLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiLib.h>
#include <Library/VirtioLib.h>
#include <Protocol/Tcg2Protocol.h>
#include "VirtioTpm.h"






// #define  TCG2_DEFAULT_MAX_COMMAND_SIZE   0x1000
// #define  TCG2_DEFAULT_MAX_RESPONSE_SIZE  0x1000
// #define TCG_EVENT_LOG_AREA_COUNT_MAX  2

// typedef struct {
//   EFI_TCG2_EVENT_LOG_FORMAT    EventLogFormat;
//   EFI_PHYSICAL_ADDRESS         Lasa;
//   UINT64                       Laml;
//   UINTN                        EventLogSize;
//   UINT8                        *LastEvent;
//   BOOLEAN                      EventLogStarted;
//   BOOLEAN                      EventLogTruncated;
//   UINTN                        Next800155EventOffset;
// } TCG_EVENT_LOG_AREA_STRUCT;

// typedef struct _TCG_DXE_DATA {
//   EFI_TCG2_BOOT_SERVICE_CAPABILITY    BsCap;
//   TCG_EVENT_LOG_AREA_STRUCT           EventLogAreaStruct[TCG_EVENT_LOG_AREA_COUNT_MAX];
//   BOOLEAN                             GetEventLogCalled[TCG_EVENT_LOG_AREA_COUNT_MAX];
//   TCG_EVENT_LOG_AREA_STRUCT           FinalEventLogAreaStruct[TCG_EVENT_LOG_AREA_COUNT_MAX];
//   EFI_TCG2_FINAL_EVENTS_TABLE         *FinalEventsTable[TCG_EVENT_LOG_AREA_COUNT_MAX];
// } TCG_DXE_DATA;
// TCG_DXE_DATA  mTcgDxeData = {
//   {
//     sizeof (EFI_TCG2_BOOT_SERVICE_CAPABILITY), // Size
//     { 1, 1 },                                  // StructureVersion
//     { 1, 1 },                                  // ProtocolVersion
//     EFI_TCG2_BOOT_HASH_ALG_SHA1,               // HashAlgorithmBitmap
//     EFI_TCG2_EVENT_LOG_FORMAT_TCG_1_2,         // SupportedEventLogs
//     TRUE,                                      // TPMPresentFlag
//     TCG2_DEFAULT_MAX_COMMAND_SIZE,             // MaxCommandSize
//     TCG2_DEFAULT_MAX_RESPONSE_SIZE,            // MaxResponseSize
//     0,                                         // ManufacturerID
//     0,                                         // NumberOfPCRBanks
//     0,                                         // ActivePcrBanks
//   },
// };

// typedef struct {
//   EFI_GUID                     *EventGuid;
//   EFI_TCG2_EVENT_LOG_FORMAT    LogFormat;
// } TCG2_EVENT_INFO_STRUCT;

// TCG2_EVENT_INFO_STRUCT  mTcg2EventInfo[] = {
//   { &gTcgEventEntryHobGuid,  EFI_TCG2_EVENT_LOG_FORMAT_TCG_1_2 },
//   { &gTcgEvent2EntryHobGuid, EFI_TCG2_EVENT_LOG_FORMAT_TCG_2   },
// };

typedef struct {
  TPMI_ALG_HASH    HashAlgo;
  UINT16           HashSize;
  UINT32           HashMask;
} INTERNAL_HASH_INFO;
STATIC INTERNAL_HASH_INFO  mHashInfo[] = {
  { TPM_ALG_SHA1,    SHA1_DIGEST_SIZE,    HASH_ALG_SHA1    },
  { TPM_ALG_SHA256,  SHA256_DIGEST_SIZE,  HASH_ALG_SHA256  },
  { TPM_ALG_SM3_256, SM3_256_DIGEST_SIZE, HASH_ALG_SM3_256 },
  { TPM_ALG_SHA384,  SHA384_DIGEST_SIZE,  HASH_ALG_SHA384  },
  { TPM_ALG_SHA512,  SHA512_DIGEST_SIZE,  HASH_ALG_SHA512  },
};

/**
  This function dump PCR event.

  @param[in]  EventHdr     TCG PCR event structure.
**/
VOID
DumpEvent (
  IN TCG_PCR_EVENT_HDR  *EventHdr
  )
{
  UINTN  Index;

  DEBUG ((DEBUG_INFO, "  Event:\n"));
  DEBUG ((DEBUG_INFO, "    PCRIndex  - %d\n", EventHdr->PCRIndex));
  DEBUG ((DEBUG_INFO, "    EventType - 0x%08x\n", EventHdr->EventType));
  DEBUG ((DEBUG_INFO, "    Digest    - "));
  for (Index = 0; Index < sizeof (TCG_DIGEST); Index++) {
    DEBUG ((DEBUG_INFO, "%02x ", EventHdr->Digest.digest[Index]));
  }

  DEBUG ((DEBUG_INFO, "\n"));
  DEBUG ((DEBUG_INFO, "    EventSize - 0x%08x\n", EventHdr->EventSize));
  //InternalDumpHex ((UINT8 *)(EventHdr + 1), EventHdr->EventSize);
}

UINT16
EFIAPI
GetHashSizeFromAlgo (
  IN TPMI_ALG_HASH  HashAlgo
  )
{
  UINTN  Index;

  for (Index = 0; Index < sizeof (mHashInfo)/sizeof (mHashInfo[0]); Index++) {
    if (mHashInfo[Index].HashAlgo == HashAlgo) {
      return mHashInfo[Index].HashSize;
    }
  }

  return 0;
}

/**
  This function dump PCR event 2.

  @param[in]  TcgPcrEvent2     TCG PCR event 2 structure.
**/
VOID
DumpEvent2 (
  IN TCG_PCR_EVENT2  *TcgPcrEvent2
  )
{
  UINTN          Index;
  UINT32         DigestIndex;
  UINT32         DigestCount;
  TPMI_ALG_HASH  HashAlgo;
  UINT32         DigestSize;
  UINT8          *DigestBuffer;
  UINT32         EventSize;
  //UINT8          *EventBuffer;

  DEBUG ((DEBUG_INFO, "  Event:\n"));
  DEBUG ((DEBUG_INFO, "    PCRIndex  - %d\n", TcgPcrEvent2->PCRIndex));
  DEBUG ((DEBUG_INFO, "    EventType - 0x%08x\n", TcgPcrEvent2->EventType));

  DEBUG ((DEBUG_INFO, "    DigestCount: 0x%08x\n", TcgPcrEvent2->Digest.count));

  DigestCount  = TcgPcrEvent2->Digest.count;
  HashAlgo     = TcgPcrEvent2->Digest.digests[0].hashAlg;
  DigestBuffer = (UINT8 *)&TcgPcrEvent2->Digest.digests[0].digest;
  for (DigestIndex = 0; DigestIndex < DigestCount; DigestIndex++) {
    DEBUG ((DEBUG_INFO, "      HashAlgo : 0x%04x\n", HashAlgo));
    DEBUG ((DEBUG_INFO, "      Digest(%d): ", DigestIndex));
    DigestSize = GetHashSizeFromAlgo (HashAlgo);
    for (Index = 0; Index < DigestSize; Index++) {
      DEBUG ((DEBUG_INFO, "%02x ", DigestBuffer[Index]));
    }

    DEBUG ((DEBUG_INFO, "\n"));
    //
    // Prepare next
    //
    CopyMem (&HashAlgo, DigestBuffer + DigestSize, sizeof (TPMI_ALG_HASH));
    DigestBuffer = DigestBuffer + DigestSize + sizeof (TPMI_ALG_HASH);
  }

  DEBUG ((DEBUG_INFO, "\n"));
  DigestBuffer = DigestBuffer - sizeof (TPMI_ALG_HASH);

  CopyMem (&EventSize, DigestBuffer, sizeof (TcgPcrEvent2->EventSize));
  DEBUG ((DEBUG_INFO, "    EventSize - 0x%08x\n", EventSize));
  //EventBuffer = DigestBuffer + sizeof (TcgPcrEvent2->EventSize);
  //InternalDumpHex (EventBuffer, EventSize);
}


/**
  This function returns size of TCG PCR event 2.

  @param[in]  TcgPcrEvent2     TCG PCR event 2 structure.

  @return size of TCG PCR event 2.
**/
UINTN
GetPcrEvent2Size (
  IN TCG_PCR_EVENT2  *TcgPcrEvent2
  )
{
  UINT32         DigestIndex;
  UINT32         DigestCount;
  TPMI_ALG_HASH  HashAlgo;
  UINT32         DigestSize;
  UINT8          *DigestBuffer;
  UINT32         EventSize;
  UINT8          *EventBuffer;

  DigestCount  = TcgPcrEvent2->Digest.count;
  HashAlgo     = TcgPcrEvent2->Digest.digests[0].hashAlg;
  DigestBuffer = (UINT8 *)&TcgPcrEvent2->Digest.digests[0].digest;
  for (DigestIndex = 0; DigestIndex < DigestCount; DigestIndex++) {
    DigestSize = GetHashSizeFromAlgo (HashAlgo);
    //
    // Prepare next
    //
    CopyMem (&HashAlgo, DigestBuffer + DigestSize, sizeof (TPMI_ALG_HASH));
    DigestBuffer = DigestBuffer + DigestSize + sizeof (TPMI_ALG_HASH);
  }

  DigestBuffer = DigestBuffer - sizeof (TPMI_ALG_HASH);

  CopyMem (&EventSize, DigestBuffer, sizeof (TcgPcrEvent2->EventSize));
  EventBuffer = DigestBuffer + sizeof (TcgPcrEvent2->EventSize);

  return (UINTN)EventBuffer + EventSize - (UINTN)TcgPcrEvent2;
}

/**
  This function get size of TCG_EfiSpecIDEventStruct.

  @param[in]  TcgEfiSpecIdEventStruct     A pointer to TCG_EfiSpecIDEventStruct.
**/
UINTN
GetTcgEfiSpecIdEventStructSize (
  IN TCG_EfiSpecIDEventStruct  *TcgEfiSpecIdEventStruct
  )
{
  TCG_EfiSpecIdEventAlgorithmSize  *DigestSize;
  UINT8                            *VendorInfoSize;
  UINT32                           NumberOfAlgorithms;

  CopyMem (&NumberOfAlgorithms, TcgEfiSpecIdEventStruct + 1, sizeof (NumberOfAlgorithms));

  DigestSize     = (TCG_EfiSpecIdEventAlgorithmSize *)((UINT8 *)TcgEfiSpecIdEventStruct + sizeof (*TcgEfiSpecIdEventStruct) + sizeof (NumberOfAlgorithms));
  VendorInfoSize = (UINT8 *)&DigestSize[NumberOfAlgorithms];
  return sizeof (TCG_EfiSpecIDEventStruct) + sizeof (UINT32) + (NumberOfAlgorithms * sizeof (TCG_EfiSpecIdEventAlgorithmSize)) + sizeof (UINT8) + (*VendorInfoSize);
}

/**
  This function dump event log.

  @param[in]  EventLogFormat     The type of the event log for which the information is requested.
  @param[in]  EventLogLocation   A pointer to the memory address of the event log.
  @param[in]  EventLogLastEntry  If the Event Log contains more than one entry, this is a pointer to the
                                 address of the start of the last entry in the event log in memory.
  @param[in]  FinalEventsTable   A pointer to the memory address of the final event table.
**/
VOID
DumpEventLog (
  IN EFI_TCG2_EVENT_LOG_FORMAT    EventLogFormat,
  IN EFI_PHYSICAL_ADDRESS         EventLogLocation,
  IN EFI_PHYSICAL_ADDRESS         EventLogLastEntry
  )
{
  TCG_PCR_EVENT_HDR         *EventHdr;
  TCG_PCR_EVENT2            *TcgPcrEvent2;
  TCG_EfiSpecIDEventStruct  *TcgEfiSpecIdEventStruct;
 // UINTN                     NumberOfEvents;

  DEBUG ((DEBUG_INFO, "EventLogFormat: (0x%x)\n", EventLogFormat));

  switch (EventLogFormat) {
    case EFI_TCG2_EVENT_LOG_FORMAT_TCG_1_2:
      EventHdr = (TCG_PCR_EVENT_HDR *)(UINTN)EventLogLocation;
      while ((UINTN)EventHdr <= EventLogLastEntry) {
        DumpEvent (EventHdr);
        EventHdr = (TCG_PCR_EVENT_HDR *)((UINTN)EventHdr + sizeof (TCG_PCR_EVENT_HDR) + EventHdr->EventSize);
      }
      break;
    case EFI_TCG2_EVENT_LOG_FORMAT_TCG_2:
      //
      // Dump first event
      //
      EventHdr = (TCG_PCR_EVENT_HDR *)(UINTN)EventLogLocation;
      DumpEvent (EventHdr);
      
      DEBUG ((DEBUG_INFO, "DumpEvent: first event end ===== \n"));

      TcgEfiSpecIdEventStruct = (TCG_EfiSpecIDEventStruct *)(EventHdr + 1);
      //DumpTcgEfiSpecIdEventStruct (TcgEfiSpecIdEventStruct);
    
       DEBUG ((DEBUG_INFO, "DumpEvent: DumpTcgEfiSpecIdEventStruct end ==== \n"));


      TcgPcrEvent2 = (TCG_PCR_EVENT2 *)((UINTN)TcgEfiSpecIdEventStruct + GetTcgEfiSpecIdEventStructSize (TcgEfiSpecIdEventStruct));
      while ((UINTN)TcgPcrEvent2 <= EventLogLastEntry) {
        DumpEvent2 (TcgPcrEvent2);
        TcgPcrEvent2 = (TCG_PCR_EVENT2 *)((UINTN)TcgPcrEvent2 + GetPcrEvent2Size (TcgPcrEvent2));
        DEBUG ((DEBUG_INFO, "DumpEvent:  event end ===== \n"));
      }

      break;
  }

  return;
}


STATIC
EFI_STATUS
EFIAPI
GetEventLog(
  IN EFI_TCG2_EVENT_LOG_FORMAT    EventLogFormat,
  IN EFI_PHYSICAL_ADDRESS         *EventLogLocation,
  IN EFI_PHYSICAL_ADDRESS         *EventLogLastEntry,
  //IN EFI_TCG2_FINAL_EVENTS_TABLE  *FinalEventsTable,
  OUT BOOLEAN                   *EventLogTruncated
)
{
    EFI_STATUS     Status;
    EFI_TCG2_PROTOCOL                 *Tcg2ProtocolCom; 
    EFI_TCG2_BOOT_SERVICE_CAPABILITY  Tcg2ProtocolCapability;
    Tcg2ProtocolCom = NULL;
    Status       = gBS->LocateProtocol (&gEfiTcg2ProtocolGuid, NULL, (VOID **)&Tcg2ProtocolCom);

    if (EFI_ERROR (Status)) {
    //
    // Tcg2 protocol is not installed. So, TPM2 is not present.
    //
    DEBUG ((DEBUG_VERBOSE, "Tcg2Protocol is not installed. - %r\n", Status));
  } else {
    Tcg2ProtocolCapability.Size = (UINT8)sizeof (Tcg2ProtocolCapability);
    Status                      = Tcg2ProtocolCom->GetCapability (Tcg2ProtocolCom, &Tcg2ProtocolCapability);
    if (EFI_ERROR (Status) || (!Tcg2ProtocolCapability.TPMPresentFlag)) {
      //
      // TPM device doesn't work or activate.
      //
      DEBUG ((DEBUG_ERROR, "TPMPresentFlag=FALSE %r\n", Status));
      Tcg2ProtocolCom = NULL;
    }
  }


  //get event log
   EventLogFormat = EFI_TCG2_EVENT_LOG_FORMAT_TCG_2;
   Status = Tcg2ProtocolCom->GetEventLog(Tcg2ProtocolCom,EventLogFormat,EventLogLocation,EventLogLastEntry,EventLogTruncated);
   DumpEventLog(EventLogFormat,*EventLogLocation,*EventLogLastEntry);
     

  

  return EFI_SUCCESS;
}

STATIC
EFI_STATUS
EFIAPI
VirtioGetCapability (
  IN EFI_TCG2_PROTOCOL                     *This,
  IN OUT EFI_TCG2_BOOT_SERVICE_CAPABILITY  *ProtocolCapability
    )
{

  return EFI_SUCCESS;
}


STATIC
EFI_STATUS
EFIAPI
VirtioGetActivePcrBanks (
  IN  EFI_TCG2_PROTOCOL  *This,
  OUT UINT32             *ActivePcrBanks
  )
{
  return EFI_SUCCESS;
}

STATIC
EFI_STATUS
EFIAPI
VirtioSubmitCommand (
  IN EFI_TCG2_PROTOCOL  *This,
  IN UINT32             InputParameterBlockSize,
  IN UINT8              *InputParameterBlock,
  IN UINT32             OutputParameterBlockSize,
  IN UINT8              *OutputParameterBlock
)
{
    volatile UINT8                *HostBufferRequest;
    volatile UINT8                *HostBufferResponse;
    EFI_STATUS          Status;
    EFI_PHYSICAL_ADDRESS  DeviceAddressRequest;
    EFI_PHYSICAL_ADDRESS  DeviceAddressResponse;
    VOID                  *MappingRequest;
    VOID                  *MappingResponse;


    //step 1 : cast the   protocol a device
    VIRTIO_TPM_DEV *Dev;
    Dev =  VIRTIO_TPM_FROM_TCG(This);

    //step 2 : check input valid ? 
    //TODO


    //step 3 : allocate a host-side buffer for the command
    HostBufferRequest = (volatile UINT8 *)AllocateZeroPool(InputParameterBlockSize);
    HostBufferResponse = (volatile UINT8 *)AllocateZeroPool(OutputParameterBlockSize);
    if (HostBufferRequest == NULL || HostBufferResponse == NULL){
        //goto error
        DEBUG ((DEBUG_WARN, "tpm driver VirtioSubmitCommand 3 allocate failue \n"));
    }
    CopyMem((void *)HostBufferRequest, InputParameterBlock, InputParameterBlockSize);

    //step 4 : map the host buffer for device to read  
    // VirtioOperationBusMasterWrite  表示设备向内存写数据
    // VirtioOperationBusMasterRead   表示设备读取内存数据
    DEBUG ((DEBUG_WARN, "tpm driver VirtioSubmitCommand 4 map share buffer \n"));
    Status = VirtioMapAllBytesInSharedBuffer(
             Dev->VirtIo,
             VirtioOperationBusMasterRead, // 假设是将数据写入设备
             (void *)HostBufferRequest,
             InputParameterBlockSize,
             &DeviceAddressRequest,
             &MappingRequest
           );
    Status = VirtioMapAllBytesInSharedBuffer(
            Dev->VirtIo,
            VirtioOperationBusMasterWrite,
            (void *) HostBufferResponse,
            OutputParameterBlockSize,
            &DeviceAddressResponse,
            &MappingResponse
           ); 
    
    if (EFI_ERROR(Status)) {
        goto FreeBuffer;
    }

    // UINT16 DescIndex;
    // Status = VirtioPrepareRing(Dev, &DescIndex);
    DESC_INDICES Indices;
    VirtioPrepare (&Dev->Ring, &Indices);
    VirtioAppendDesc (
      &Dev->Ring,
      DeviceAddressRequest,
      InputParameterBlockSize,
      VRING_DESC_F_NEXT, //VRING_DESC_F_WRITE,
      &Indices
      );
    VirtioAppendDesc (
      &Dev->Ring,
      DeviceAddressResponse,
      OutputParameterBlockSize,
      VRING_DESC_F_WRITE,
      &Indices
      );

    DEBUG ((DEBUG_WARN, " \n tpm driver VirtioSubmitCommand :physical set successful\n"));
    UINT32                Len;
    if (VirtioFlush (Dev->VirtIo, 0, &Dev->Ring, &Indices, &Len) !=
        EFI_SUCCESS)
    {
      Status = EFI_DEVICE_ERROR;
      goto UnmapBufferRequest;
    }

  DEBUG ((DEBUG_WARN, " \n tpm driver VirtioSubmitCommand :send message successful\n"));
  Status = Dev->VirtIo->UnmapSharedBuffer (Dev->VirtIo, MappingRequest);
  if (EFI_ERROR (Status)) {
    Status = EFI_DEVICE_ERROR;
    goto UnmapBufferResponse;
  }
  Status = Dev->VirtIo->UnmapSharedBuffer (Dev->VirtIo, MappingResponse);
  if (EFI_ERROR (Status)) {
    Status = EFI_DEVICE_ERROR;
    goto FreeBuffer;
  }

     DEBUG ((DEBUG_WARN, " \n tpm driver VirtioSubmitCommand :Comand len id %d\n",Len));


     DEBUG ((DEBUG_WARN, " \n tpm driver VirtioSubmitCommand :physical set release\n"));


    for (UINTN Index = 0; Index < InputParameterBlockSize; Index++) {
        InputParameterBlock[Index] = HostBufferRequest[Index];
    }

    for (UINTN Index = 0; Index < OutputParameterBlockSize; Index++) {
        OutputParameterBlock[Index] = HostBufferResponse[Index];
    }
    DEBUG ((DEBUG_WARN, " \n tpm driver VirtioSubmitCommand :command len %08x \n",InputParameterBlockSize));
    for (UINTN Index = 0; Index < InputParameterBlockSize; ++Index) {
        DEBUG((DEBUG_WARN," %d -> (%04x) \n",Index,*((UINT8 *)InputParameterBlock + Index) ));  ///*((UINT32 *)HostBuffer + Index
    }
    DEBUG ((DEBUG_WARN, " \n tpm driver VirtioSubmitCommand :response len %08x \n",OutputParameterBlockSize));
    for (UINTN Index = 0; Index < OutputParameterBlockSize; ++Index) {
        DEBUG((DEBUG_WARN," %d -> (%04x) \n",Index,*((UINT8 *)OutputParameterBlock + Index) ));  ///*((UINT32 *)HostBuffer + Index
    }



    Status = EFI_SUCCESS;

UnmapBufferRequest:
  //
  // If we are reached here due to the error then unmap the buffer otherwise
  // the buffer is already unmapped after VirtioFlush().
  //
  if (EFI_ERROR (Status)) {
    Dev->VirtIo->UnmapSharedBuffer (Dev->VirtIo, MappingRequest);
  }


UnmapBufferResponse:
  if (EFI_ERROR (Status)) {
    Dev->VirtIo->UnmapSharedBuffer (Dev->VirtIo, MappingResponse);
  }



  

FreeBuffer:
  FreePool ((VOID *)HostBufferRequest);
  FreePool ((VOID *)HostBufferResponse);
  return Status;
    


    // VRING *ring;
    // UINT16 AvailIdx;
    // UINT16 Index;
    // ring  =  &Dev->Ring;
    // AvailIdx = *ring->Avail.Idx % ring->QueueSize;
    // Index = ring->Avail.Ring[AvailIdx];   //->Avail->Ring[AvailIdx];
    // DEBUG ((DEBUG_WARN, "tpm driver VirtioSubmitCommand 5 and  AvailIdx is %d  \n",AvailIdx));

    // ring->Desc[Index].Addr  = DeviceAddress;
    // ring->Desc[Index].Len   = InputParameterBlockSize;
    // ring->Desc[Index].Flags = 0;
    // ring->Desc[Index].Next = 0; 



    //notify the device that the command is ready 

//     DEBUG ((DEBUG_WARN, "tpm driver VirtioSubmitCommand 6  data is ready \n"));

//     MemoryFence(); // 确保描述符的写操作完成
//     ring->Avail.Idx++; // 递增可用环的索引
//     MemoryFence(); // 确保索引更新对设备可见

//     Dev->VirtIo->SetQueueNotify(Dev->VirtIo, 0);
//     return EFI_SUCCESS;
 }



// STATIC 
// EFI_STATUS
// EFIAPI
// ReadAndSendEventLog(
//     IN EFI_TCG2_PROTOCOL *Tcg2Protocol
// ) {
//     EFI_STATUS Status;
//     EFI_TCG2_EVENT_LOG_FORMAT LogFormat;
//     EFI_PHYSICAL_ADDRESS LogLocation, LogLastEntry;
//     BOOLEAN Truncated;

//     // 获取事件日志
//     Status = Tcg2Protocol->GetEventLog(
//         Tcg2Protocol,
//         EFI_TCG2_EVENT_LOG_FORMAT_TCG_2,
//         &LogLocation,
//         &LogLastEntry,
//         &Truncated
//     );
//     if (EFI_ERROR(Status)) {
//         DEBUG((DEBUG_ERROR, "GetEventLog failed: %r\n", Status));
//         return Status;
//     }

//     // 计算事件日志的大小
//     UINTN EventLogSize = (UINTN)(LogLastEntry - LogLocation);
//     if (Truncated) {
//         DEBUG((DEBUG_WARN, "The event log was truncated, data may be missing.\n"));
//     }

//     // 分配缓冲区以发送事件日志
//     UINT8 *EventLogBuffer = AllocatePool(EventLogSize);
//     if (EventLogBuffer == NULL) {
//         DEBUG((DEBUG_ERROR, "Failed to allocate memory for event log buffer.\n"));
//         return EFI_OUT_OF_RESOURCES;
//     }

//     // 复制事件日志到缓冲区
//     CopyMem(EventLogBuffer, (VOID *)(UINTN)LogLocation, EventLogSize);

//     // 发送事件日志到 TPM 设备
//     Status = VirtioTpmSendCommand(
//         /* EFI_TCG_PROTOCOL */ NULL, // 假设的 TCG 协议实例
//         /* TpmInputParameterBlockSize */ EventLogSize,
//         /* TpmInputParameterBlock */ EventLogBuffer,
//         /* TpmOutputParameterBlockSize */ 0,
//         /* TpmOutputParameterBlock */ NULL
//     );
//     if (EFI_ERROR(Status)) {
//         DEBUG((DEBUG_ERROR, "VirtioTpmSendCommand failed: %r\n", Status));
//     } else {
//         // 如果需要，接收 TPM 设备的响应
//         // 假设 ResponseSize 为预期响应大小
//         UINT32 ResponseSize = 1024;
//         UINT8 *ResponseBuffer = AllocatePool(ResponseSize);
//         if (ResponseBuffer == NULL) {
//             DEBUG((DEBUG_ERROR, "Failed to allocate memory for response buffer.\n"));
//             FreePool(EventLogBuffer);
//             return EFI_OUT_OF_RESOURCES;
//         }

//         Status = VirtioTpmRecvCommand(
//             /* EFI_TCG_PROTOCOL */ NULL, // 假设的 TCG 协议实例
//             /* TpmInputParameterBlockSize */ 0,
//             /* TpmInputParameterBlock */ NULL,
//             /* TpmOutputParameterBlockSize */ ResponseSize,
//             /* TpmOutputParameterBlock */ ResponseBuffer
//         );
//         if (EFI_ERROR(Status)) {
//             DEBUG((DEBUG_ERROR, "VirtioTpmRecvCommand failed: %r\n", Status));
//         }

//         // 处理响应...

//         FreePool(ResponseBuffer);
//     }

//     FreePool(EventLogBuffer);
//     return Status;
// }







// // Send a command to the TPM device.
// STATIC 
// EFI_STATUS
// EFIAPI
// VirtioTpmSendCommand(
//     IN EFI_TCG_PROTOCOL   *This,
//     IN UINT32             TpmInputParameterBlockSize,
//     IN UINT8              *TpmInputParameterBlock,
//     IN UINT32             TpmOutputParameterBlockSize,
//     IN OUT UINT8          *TpmOutputParameterBlock
// ) {
//     if (This == NULL || TpmInputParameterBlock == NULL || TpmOutputParameterBlock == NULL) {
//         return EFI_INVALID_PARAMETER;
//     }

//     // Retrieve the context from the EFI_TCG_PROTOCOL.
//     VIRTIO_TPM_DEVICE *VirtioTpmDevice = (VIRTIO_TPM_DEVICE *)(This->This);

//     // Send the command to TPM via Virtio.
//     // Note: Actual implementation of virtio-based transmission depends on your environment.
//     EFI_STATUS Status = VirtioTpmDevice->VirtIo->Send(
//         VirtioTpmDevice->VirtIo,
//         TpmInputParameterBlockSize,
//         TpmInputParameterBlock,
//         0 // Queue number, assuming 0 is for outgoing commands
//     );

//     return Status;
// }

// // Receive a response from the TPM device.
// STATIC 
// EFI_STATUS
// EFIAPI
// VirtioTpmRecvCommand(
//     IN EFI_TCG_PROTOCOL   *This,
//     IN UINT32             TpmInputParameterBlockSize,
//     IN UINT8              *TpmInputParameterBlock,
//     IN UINT32             TpmOutputParameterBlockSize,
//     IN OUT UINT8          *TpmOutputParameterBlock
// ) {
//     if (This == NULL || TpmInputParameterBlock == NULL || TpmOutputParameterBlock == NULL) {
//         return EFI_INVALID_PARAMETER;
//     }

//     // Retrieve the context from the EFI_TCG_PROTOCOL.
//     VIRTIO_TPM_DEVICE *VirtioTpmDevice = (VIRTIO_TPM_DEVICE *)(This->This);

//     // Receive the response from TPM via Virtio.
//     // Note: Actual implementation of virtio-based reception depends on your environment.
//     EFI_STATUS Status = VirtioTpmDevice->VirtIo->Receive(
//         VirtioTpmDevice->VirtIo,
//         TpmOutputParameterBlockSize,
//         TpmOutputParameterBlock,
//         1 // Queue number, assuming 1 is for incoming responses
//     );

//     return Status;
// }



// STATIC 
// EFI_STATUS
// EFIAPI
// VirtioTpmDriverBindingSupported(
//    IN EFI_DRIVER_BINDING_PROTOCOL *This,
//    IN EFI_HANDLE                  DeviceHandle,
//    IN EFI_DEVICE_PATH_PROTOCOL    *RemainingDevicePath 
// )
// {
//     EFI_STATUS              Status;
//     VIRTIO_DEVICE_PROTOCOL  *VirtIo;
    
//     DEBUG ((DEBUG_WARN, "tpm driver binding support \n"));
//     Status = gBS->OpenProtocol (
//                   DeviceHandle,               // candidate device
//                   &gVirtioDeviceProtocolGuid, // for generic VirtIo access
//                   (VOID **)&VirtIo,           // handle to instantiate
//                   This->DriverBindingHandle,  // requestor driver identity
//                   DeviceHandle,               // ControllerHandle, according to
//                                               // the UEFI Driver Model
//                   EFI_OPEN_PROTOCOL_BY_DRIVER // get exclusive VirtIo access to
//                                               // the device; to be released
//                   );
//     if (EFI_ERROR (Status)) {
//         return Status;
//     }
//     DEBUG ((DEBUG_WARN, "tpm driver binding support : openProtocol successful with id is ( %d )\n",VirtIo->SubSystemDeviceId));    



//     return EFI_NOT_FOUND;
// }

STATIC 
EFI_STATUS
EFIAPI
VirtioTpmDriverBindingSupported(
    IN EFI_DRIVER_BINDING_PROTOCOL *This,
    IN EFI_HANDLE                  DeviceHandle,
    IN EFI_DEVICE_PATH_PROTOCOL    *RemainingDevicePath
) {
    EFI_STATUS              Status;
    VIRTIO_DEVICE_PROTOCOL  *VirtIo;

    // 尝试打开VirtIO协议
    Status = gBS->OpenProtocol(
        DeviceHandle,
        &gVirtioDeviceProtocolGuid,
        (VOID **)&VirtIo,
        This->DriverBindingHandle,
        DeviceHandle,
        EFI_OPEN_PROTOCOL_BY_DRIVER
    );

    // 如果打开失败，返回错误状态
    if (EFI_ERROR(Status)) {
        return Status;
    }

    // 检查子系统设备ID是否是TPM //VIRTIO_SUBSYSTEM_ENTROPY_SOURCE  VIRTIO_SUBSYSTEM_TPM
    if (VirtIo->SubSystemDeviceId == VIRTIO_SUBSYSTEM_TPM) {
        DEBUG ((DEBUG_WARN, "tpm driver binding support found tpm device \n"));
        Status = EFI_SUCCESS;
    } else {
        Status = EFI_UNSUPPORTED;
    }




    DEBUG ((DEBUG_WARN, "subsystem device_id: %d\n",VirtIo->SubSystemDeviceId));

    // 关闭协议
    gBS->CloseProtocol(
        DeviceHandle,
        &gVirtioDeviceProtocolGuid,
        This->DriverBindingHandle,
        DeviceHandle
    );

    return Status;
}





// STATIC 
// EFI_STATUS
// EFIAPI
// VirtioTpmDriverBindingStart(
//     IN EFI_DRIVER_BINDING_PROTOCOL *This,
//     IN EFI_HANDLE                  DeviceHandle,
//     IN EFI_DEVICE_PATH_PROTOCOL    *RemainingDevicePath
// )
// {
  
//     DEBUG ((DEBUG_WARN, "tpm driver binding start \n"));
//     return EFI_SUCCESS;
// }

STATIC 
EFI_STATUS
EFIAPI
VirtioTpmDriverBindingStop(
    IN EFI_DRIVER_BINDING_PROTOCOL *This,
    IN EFI_HANDLE                  DeviceHandle,
    IN UINTN                       NumberOfChildren,
    IN EFI_HANDLE                  *ChildHandleBuffer
)
{   
    DEBUG ((DEBUG_WARN, "tpm driver binding stopped \n"));
    return EFI_SUCCESS;
}



STATIC 
EFI_STATUS
EFIAPI
VirtioTpmInit(
    IN OUT VIRTIO_TPM_DEV *DEV
)
{
    UINT8 NextDevStat;
    EFI_STATUS Status;
    UINT16 QueueSize = 0;
    UINT64 Features;
    UINT64 RingBaseShift;

    Status = VirtioRingInit (DEV->VirtIo, QueueSize, &DEV->Ring);

    //step1 reset device 
    DEBUG((DEBUG_WARN, "VIRTIOTPM:tpm init  step 1! \n"));
    NextDevStat = 0;
    Status = DEV->VirtIo->SetDeviceStatus(DEV->VirtIo, NextDevStat);
    if (EFI_ERROR(Status)){
        goto Failed;
    }

    //setp2 acknowledge device presence 
    DEBUG((DEBUG_WARN, "VIRTIOTPM:tpm init  step 2! \n"));
    NextDevStat |= VSTAT_ACK;
    Status = DEV->VirtIo->SetDeviceStatus(DEV->VirtIo, NextDevStat);
    if (EFI_ERROR(Status)){
        goto Failed;
    }

    //step3 we know to drive it
    DEBUG((DEBUG_WARN, "VIRTIOTPM:tpm init  step 3! \n"));
    NextDevStat |= VSTAT_DRIVER;
        Status = DEV->VirtIo->SetDeviceStatus(DEV->VirtIo, NextDevStat);
    if (EFI_ERROR(Status)){
        goto Failed;
    }
    

    Status = DEV->VirtIo->SetPageSize (DEV->VirtIo, EFI_PAGE_SIZE);
    if (EFI_ERROR (Status)) {
        goto Failed;
    }

    //step4 retrive and validate feature
    DEBUG((DEBUG_WARN, "VIRTIOTPM:tpm init  step 4! \n"));
    Status  =  DEV->VirtIo->GetDeviceFeatures(DEV->VirtIo, &Features);
    if (EFI_ERROR (Status)) {
        goto Failed;
    }
    DEBUG((DEBUG_WARN, "VIRTIOTPM:tpm init  step 4! | features is %ld\n", Features));
    //TODO 需要验证feature
    Features &= VIRTIO_F_VERSION_1 | VIRTIO_F_IOMMU_PLATFORM;

    if (DEV->VirtIo->Revision >= VIRTIO_SPEC_REVISION (1, 0, 0)) {
    Status = Virtio10WriteFeatures (DEV->VirtIo, Features, &NextDevStat);
        if (EFI_ERROR (Status)) {
             goto Failed;
        }
    }

    //step 5 allocate request virtqueue 
    DEBUG((DEBUG_WARN, "VIRTIOTPM:tpm init  step 5! \n"));
    Status = DEV->VirtIo->SetQueueSel(DEV->VirtIo, 0);

    Status = DEV->VirtIo->GetQueueNumMax (DEV->VirtIo, &QueueSize);
    if (EFI_ERROR (Status)) {
        goto Failed;
    }
    DEBUG((DEBUG_WARN, "VIRTIOTPM:tpm init  step 5! queuesize is : %d \n",QueueSize));
    if (QueueSize < 1) {
        Status = EFI_UNSUPPORTED;
        goto Failed;
    }
    //VRING ring ;

    Status = VirtioRingInit (DEV->VirtIo, QueueSize, &(DEV->Ring));
        if (EFI_ERROR (Status)) {
        goto Failed;
    }
    DEBUG((DEBUG_WARN, "VIRTIOTPM:tpm init  step 5! queuesize allocate success!! \n"));

    Status = VirtioRingMap (
        DEV->VirtIo,
        &DEV->Ring,
        &RingBaseShift,
        &DEV->RingMap
        );
  if (EFI_ERROR (Status)) {
    goto ReleaseQueue;
  }

  //step 6: set queue size
  Status = DEV->VirtIo->SetQueueNum (DEV->VirtIo, QueueSize);
  if (EFI_ERROR (Status)) {
    goto UnmapQueue;
  }
  // set queue align  对齐  以 EFI_PAGE_SIZE  为标准 ）
  Status = DEV->VirtIo->SetQueueAlign (DEV->VirtIo, EFI_PAGE_SIZE);
  if (EFI_ERROR (Status)) {
    goto UnmapQueue;
  }
  DEBUG((DEBUG_WARN, "VIRTIOTPM:tpm init  step 6! set queuesize and align\n"));

  //setp 7 tell device  the virtqueue address 
  Status = DEV->VirtIo->SetQueueAddress (
                          DEV->VirtIo,
                          &DEV->Ring,
                          RingBaseShift
                          );
  if (EFI_ERROR (Status)) {
    goto UnmapQueue;
  }

  NextDevStat |= VSTAT_DRIVER_OK;
  Status       = DEV->VirtIo->SetDeviceStatus (DEV->VirtIo, NextDevStat);
  if (EFI_ERROR (Status)) {
    goto UnmapQueue;
  }
  
  DEV->Tcg.GetCapability  = VirtioGetCapability;
  DEV->Tcg.GetActivePcrBanks = VirtioGetActivePcrBanks;
//   DEV->Tcg.GetEventLog = VirtioGetEventLog;
//   DEV->Tcg.GetResultOfSetActivePcrBanks = VirtioGetResultOfSetActivePcrBanks;
//   DEV->Tcg.HashLogExtendEvent = VirtioHashLogExtendEvent;
//   DEV->Tcg.SetActivePcrBanks = VirtioSetActivePcrBanks;
   DEV->Tcg.SubmitCommand = VirtioSubmitCommand;



return EFI_SUCCESS;

    // return Status;

UnmapQueue:
  DEV->VirtIo->UnmapSharedBuffer (DEV->VirtIo, DEV->RingMap);

ReleaseQueue:
  VirtioRingUninit (DEV->VirtIo, &DEV->Ring);

Failed:
    DEBUG((DEBUG_WARN, "VIRTIOTPM:tpm init error! \n"));
    return EFI_UNSUPPORTED;
}






STATIC
VOID
EFIAPI
VirtioTpmExitBoot (
IN EFI_EVENT Event,
IN VOID *Context
)
{
    VIRTIO_TPM_DEV *DEV;
    DEBUG((DEBUG_WARN, "VIRTIOTPM:tpm exit boot \n"));

    DEV = Context;
    DEV->VirtIo->SetDeviceStatus(DEV->VirtIo, 0);
}


STATIC
VOID
EFIAPI
VirtioTpmUninit (
  IN OUT VIRTIO_TPM_DEV  *Dev
  )
{
  //
  // Reset the virtual device -- see virtio-0.9.5, 2.2.2.1 Device Status. When
  // VIRTIO_CFG_WRITE() returns, the host will have learned to stay away from
  // the old comms area.
  //
  Dev->VirtIo->SetDeviceStatus (Dev->VirtIo, 0);

  Dev->VirtIo->UnmapSharedBuffer (Dev->VirtIo, Dev->RingMap);

  VirtioRingUninit (Dev->VirtIo, &Dev->Ring);
}



EFI_STATUS
EFIAPI
VirtioTpmDriverBindingStart(
    IN EFI_DRIVER_BINDING_PROTOCOL *This,
    IN EFI_HANDLE                  DeviceHandle,
    IN EFI_DEVICE_PATH_PROTOCOL    *RemainingDevicePath
) {
    EFI_STATUS              Status ;
    //Status = EFI_SUCCESS;
    //VIRTIO_DEVICE_PROTOCOL  *VirtIo;
    VIRTIO_TPM_DEV       *VTpmDev;

    DEBUG ((DEBUG_WARN, "tpm driver binding start_0 \n"));

    VTpmDev = (VIRTIO_TPM_DEV *)AllocateZeroPool (sizeof *VTpmDev);
    if (VTpmDev == NULL) {
        return EFI_OUT_OF_RESOURCES;
    }

    // 打开VirtIO协议
    Status = gBS->OpenProtocol(
        DeviceHandle,
        &gVirtioDeviceProtocolGuid,
        (VOID **)&VTpmDev->VirtIo,
        This->DriverBindingHandle,
        DeviceHandle,
        EFI_OPEN_PROTOCOL_BY_DRIVER
    );

    if (EFI_ERROR(Status)) {
        DEBUG((DEBUG_ERROR, "Failed to open VirtIO protocol: %r\n", Status));
        goto FreeVirtioTpm;
    }

    DEBUG ((DEBUG_WARN, "tpm driver binding start_0:openinit \n"));
    
    Status = VirtioTpmInit(VTpmDev);
    if (EFI_ERROR (Status)) {
        goto CloseVirtIo;
    }

    DEBUG ((DEBUG_WARN, "tpm driver binding start_0:successful  \n"));


    Status = gBS->CreateEvent (
            EVT_SIGNAL_EXIT_BOOT_SERVICES,
            TPL_CALLBACK,
            &VirtioTpmExitBoot,
            VTpmDev,
            &VTpmDev->ExitBoot
            );
    if (EFI_ERROR (Status)) {
        DEBUG ((DEBUG_WARN, "tpm driver binding start creat event unsuccessful  \n"));
        goto UninitDev;
    }
    DEBUG ((DEBUG_WARN, "tpm driver binding start creat event successful  \n"));

    VTpmDev->Signature = VIRTIO_TPM_SIG;
    Status         = gBS->InstallProtocolInterface (
                          &DeviceHandle,
                          &gEfiTcg2FinalEventsTableGuid,
                          EFI_NATIVE_INTERFACE,
                          &VTpmDev->Tcg
                          );
  if (EFI_ERROR (Status)) {
    goto CloseExitBoot;
  }



  //TODO delete it

     DEBUG ((DEBUG_WARN, "tpm driver ready to send message  \n"));
  // VOID *INPAR;
  // VOID *OUTPAR;
  // UINT8 DataToCopy[] = {0x80, 0x01, 0x00, 0x00, 0x00, 0x0B, 0x00, 0x00, 0x01, 0x43, 0x00};
  // INPAR   =  AllocateZeroPool(sizeof(DataToCopy));
  // OUTPAR  = AllocateZeroPool(100* sizeof(DataToCopy));
  // CopyMem(INPAR, DataToCopy, sizeof(DataToCopy));
  // VirtioSubmitCommand(&VTpmDev->Tcg, (UINT32)sizeof(DataToCopy),(UINT8 *)INPAR   ,(UINT32)sizeof(DataToCopy) * 100, (UINT8 *)OUTPAR);

   EFI_TCG2_EVENT_LOG_FORMAT    EventLogFormat;
   EFI_PHYSICAL_ADDRESS         EventLogLocation;
   EFI_PHYSICAL_ADDRESS         EventLogLastEntry;
   //EFI_TCG2_FINAL_EVENTS_TABLE  FinalEventsTable;
   BOOLEAN                   EventLogTruncated;
   GetEventLog(EventLogFormat,&EventLogLocation,&EventLogLastEntry,&EventLogTruncated);



 DEBUG ((DEBUG_WARN, "tpm driver ready to send message  ok !! \n"));
  return EFI_SUCCESS;

CloseExitBoot:
    gBS->CloseEvent (VTpmDev->ExitBoot);

UninitDev:
    DEBUG ((DEBUG_WARN, "tpm driver binding start_0:UninitDev  \n"));
    VirtioTpmUninit (VTpmDev);

CloseVirtIo:
  gBS->CloseProtocol (
         DeviceHandle,
         &gVirtioDeviceProtocolGuid,
         This->DriverBindingHandle,
         DeviceHandle
         );

FreeVirtioTpm:
    FreePool (VTpmDev);
    DEBUG((DEBUG_ERROR, "Failed to start Virtio TPM device: %r\n", Status));
    return Status;
}






//
// 停止设备
//
// EFI_STATUS
// EFIAPI
// VirtioTpmDriverBindingStop(
//     IN EFI_DRIVER_BINDING_PROTOCOL *This,
//     IN EFI_HANDLE                  DeviceHandle,
//     IN UINTN                       NumberOfChildren,
//     IN EFI_HANDLE                  *ChildHandleBuffer
// ) {
//     EFI_STATUS          Status;
//     VIRTIO_TPM_DEVICE   *VirtioTpm;

//     // 尝试获取与设备句柄关联的VirtioTpm设备结构体
//     Status = gBS->OpenProtocol(
//         DeviceHandle,
//         &gEfiCallerIdGuid, // 使用和Start函数中相同的标识符
//         (VOID **)&VirtioTpm,
//         This->DriverBindingHandle,
//         DeviceHandle,
//         EFI_OPEN_PROTOCOL_GET_PROTOCOL
//     );

//     if (EFI_ERROR(Status)) {
//         return Status;
//     }

//     // 从设备句柄上卸载协议接口
//     Status = gBS->UninstallProtocolInterface(
//         DeviceHandle,
//         &gEfiCallerIdGuid,
//         VirtioTpm
//     );

//     if (EFI_ERROR(Status)) {
//         return Status;
//     }

//     // 关闭VirtIO协议
//     Status = gBS->CloseProtocol(
//         DeviceHandle,
//         &gVirtioDeviceProtocolGuid,
//         This->DriverBindingHandle,
//         DeviceHandle
//     );

//     // 释放与VirtioTpm设备关联的资源
//     gBS->FreePool(VirtioTpm);

//     return EFI_SUCCESS;
// }






STATIC EFI_DRIVER_BINDING_PROTOCOL gDriverBinding = {
    &VirtioTpmDriverBindingSupported,
    &VirtioTpmDriverBindingStart,
    &VirtioTpmDriverBindingStop,
    0x10,
    NULL,
    NULL
};






STATIC 
EFI_STATUS 
EFIAPI
VirtioTpmGetDriverName(
    IN EFI_COMPONENT_NAME_PROTOCOL *This,
    IN CHAR8                       *Language,
    OUT CHAR16                     **DriverName
    )
{
     return EFI_UNSUPPORTED;
}

STATIC 
EFI_STATUS
EFIAPI 
VirtioTpmGetDeviceName(
    IN EFI_COMPONENT_NAME_PROTOCOL *This,
    IN EFI_HANDLE                  DeviceHandle,
    IN EFI_HANDLE                  ChildHandle,
    IN CHAR8                       *Language,
    OUT CHAR16                     **ControllerName
){
    return EFI_UNSUPPORTED;
}



STATIC 
EFI_COMPONENT_NAME_PROTOCOL gComponentName = {
    &VirtioTpmGetDriverName,
    &VirtioTpmGetDeviceName,
    "eng"
};

STATIC 
EFI_COMPONENT_NAME2_PROTOCOL gComponentName2 = {
    (EFI_COMPONENT_NAME2_GET_DRIVER_NAME) &VirtioTpmGetDriverName,
    (EFI_COMPONENT_NAME2_GET_CONTROLLER_NAME) &VirtioTpmGetDeviceName,
    "en"
};



EFI_STATUS 
EFIAPI 
VirtioTpmEntryPoint(
    IN EFI_HANDLE ImageHandle,
    IN EFI_SYSTEM_TABLE *SystemTable
  )
{
     
     return EfiLibInstallDriverBindingComponentName2 (
           ImageHandle,
           SystemTable,
           &gDriverBinding,
           ImageHandle,
           &gComponentName,
           &gComponentName2
           );
}