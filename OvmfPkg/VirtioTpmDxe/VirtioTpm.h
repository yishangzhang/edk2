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


#include <IndustryStandard/Virtio.h>


#define VIRTIO_TPM_SIG SIGNATURE_32 ('V', 'T', 'P', 'M')

typedef struct {
 UINT32                  Signature;
 VIRTIO_DEVICE_PROTOCOL   *VirtIo;
 EFI_EVENT                ExitBoot;
 VRING                   Ring;
 //EFI_TPM_PROTOCOL         Tpm;
} VIRTIO_TPM_DEV;


#define VIRTIO_ENTROPY_SOURCE_FROM_TPM(TpmPointer) \
         CR (TpmPointer, VIRTIO_TPM_DEV, Tpm, VIRTIO_TPM_SIG)

#endif
