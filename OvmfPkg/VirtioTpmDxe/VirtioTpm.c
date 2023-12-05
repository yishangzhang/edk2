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

#include "VirtioTpm.h"



STATIC 
EFI_STATUS
EFIAPI
VirtioTpmDriverBindingSupported(
   IN EFI_DRIVER_BINDING_PROTOCOL *This,
   IN EFI_HANDLE                  DeviceHandle,
   IN EFI_DEVICE_PATH_PROTOCOL    *RemainingDevicePath 
)
{
    DEBUG ((DEBUG_VERBOSE, "tpm driver binding support \n"));
    return EFI_SUCCESS;
}

STATIC 
EFI_STATUS
EFIAPI
VirtioTpmDriverBindingStart(
    IN EFI_DRIVER_BINDING_PROTOCOL *This,
    IN EFI_HANDLE                  DeviceHandle,
    IN EFI_DEVICE_PATH_PROTOCOL    *RemainingDevicePath
)
{
  
    DEBUG ((DEBUG_VERBOSE, "tpm driver binding start \n"));
    return EFI_SUCCESS;
}

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
    DEBUG ((DEBUG_VERBOSE, "tpm driver binding stopped \n"));
    return EFI_SUCCESS;
}







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