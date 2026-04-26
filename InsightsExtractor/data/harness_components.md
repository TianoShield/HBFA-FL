# HBFA Harness → edk2 Component Map

Total harnesses: **21**  
Components covered: **5**

## DeviceSecurityPkg  (1 harness)

| Harness | Module | edk2 Source |
|---|---|---|
| `TestSignatureList` | TestSignatureList | `edk2/DeviceSecurityPkg/TestSignatureList` |

## FatPkg  (1 harness)

| Harness | Module | edk2 Source |
|---|---|---|
| `TestPeiGpt` | FatPei | `edk2/FatPkg/FatPei` |

## MdeModulePkg  (9 harnesses)

| Harness | Module | edk2 Source |
|---|---|---|
| `TestIdentifyAtaDevice` | Bus/Ata/AhciPei | `edk2/MdeModulePkg/Bus/Ata/AhciPei` |
| `TestUsb` | Bus/Usb/UsbBusDxe | `edk2/MdeModulePkg/Bus/Usb/UsbBusDxe` |
| `TestPeiUsb` | Bus/Usb/UsbBusPei | `edk2/MdeModulePkg/Bus/Usb/UsbBusPei` |
| `TestBmpSupportLib` | Library/BaseBmpSupportLib | `edk2/MdeModulePkg/Library/BaseBmpSupportLib` |
| `TestCapsulePei` | Universal/CapsulePei/Common | `edk2/MdeModulePkg/Universal/CapsulePei/Common` |
| `TestPartition` | Universal/Disk/PartitionDxe | `edk2/MdeModulePkg/Universal/Disk/PartitionDxe` |
| `TestFileName` | Universal/Disk/UdfDxe | `edk2/MdeModulePkg/Universal/Disk/UdfDxe` |
| `TestUdf` | Universal/Disk/UdfDxe | `edk2/MdeModulePkg/Universal/Disk/UdfDxe` |
| `TestVariableSmm` | Universal/Variable/RuntimeDxe | `edk2/MdeModulePkg/Universal/Variable/RuntimeDxe` |

## OvmfPkg  (5 harnesses)

| Harness | Module | edk2 Source |
|---|---|---|
| `TestValidateTdxCfv` | EmuVariableFvbRuntimeDxe | `edk2/OvmfPkg/EmuVariableFvbRuntimeDxe` |
| `TestVirtio10Blk` | Virtio10BlkDxe | `edk2/OvmfPkg/Virtio10BlkDxe` |
| `TestVirtioBlk` | VirtioBlkDxe | `edk2/OvmfPkg/VirtioBlkDxe` |
| `TestVirtioBlkReadWrite` | VirtioBlkReadWrite | `edk2/OvmfPkg/VirtioBlkReadWrite` |
| `TestVirtioPciDevice` | VirtioPciDeviceDxe | `edk2/OvmfPkg/VirtioPciDeviceDxe` |

## SecurityPkg  (5 harnesses)

| Harness | Module | edk2 Source |
|---|---|---|
| `TestTcg2MeasureGptTable` | Library/DxeTpm2MeasureBootLib | `edk2/SecurityPkg/Library/DxeTpm2MeasureBootLib` |
| `TestTcg2MeasurePeImage` | Library/DxeTpm2MeasureBootLib | `edk2/SecurityPkg/Library/DxeTpm2MeasureBootLib` |
| `TestFmpAuthenticationLibPkcs7` | Library/FmpAuthenticationLibPkcs7 | `edk2/SecurityPkg/Library/FmpAuthenticationLibPkcs7` |
| `TestFmpAuthenticationLibRsa2048Sha256` | Library/FmpAuthenticationLibRsa2048Sha256 | `edk2/SecurityPkg/Library/FmpAuthenticationLibRsa2048Sha256` |
| `TestTpm2CommandLib` | Library/Tpm2CommandLib | `edk2/SecurityPkg/Library/Tpm2CommandLib` |
