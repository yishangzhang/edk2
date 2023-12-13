/*
 * @Author: yishangzhang 
 * @Date: 2023-11-30 12:42:23 
 * @Last Modified by: yishangzhang
 * @Last Modified time: 2023-11-30 12:46:32
 */


#ifndef _VIRTIO_TPM_DXE_H_
#define _VIRTIO_TPM_DXE_H_

#include <Protocol/ComponentName.h>
#include <Protocol/DriverBinding.h>
#include <Protocol/VirtioDevice.h>
//#include <Protocol/Rng.h>
#include <Protocol/Tcg2Protocol.h>

#include <IndustryStandard/Virtio.h>


#define VIRTIO_TPM_SIG SIGNATURE_32 ('V', 'T', 'P', 'M')

typedef struct {
 UINT32                   Signature;
 EFI_TCG2_PROTOCOL        Tcg;
 EFI_EVENT                ExitBoot;
 VRING                    Ring;
 VIRTIO_DEVICE_PROTOCOL   *VirtIo;
 VOID                     *RingMap;
} VIRTIO_TPM_DEV;


 #define VIRTIO_TPM_FROM_TCG(TpmPointer) \
          CR (TpmPointer, VIRTIO_TPM_DEV, Tcg, VIRTIO_TPM_SIG)

#endif
