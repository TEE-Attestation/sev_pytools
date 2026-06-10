# Copyright 2025 Hewlett Packard Enterprise Development LP.
# SPDX-License-Identifier: MIT
#
# AMD SEV-SNP attestation report parsing and data structure definitions.

import struct
from dataclasses import dataclass, fields
from enum import Enum
from typing import Optional

from .guest_policy import GuestPolicy
from .platform_info import PlatformInfo
from .sev_logging import get_logger
from .signature import Signature

logger = get_logger(__name__)


@dataclass
class Version:
    """
    Version
    Description: Represents a semver formatted version
    """

    major: int
    minor: int
    build: int

    def __str__(self) -> str:
        return f"{self.major}.{self.minor}.{self.build}"

    def __eq__(self, other) -> bool:
        """Check if two versions are equal"""
        if not isinstance(other, Version):
            return False
        return (self.major, self.minor, self.build) == (
            other.major,
            other.minor,
            other.build,
        )

    def __lt__(self, other) -> bool:
        """Check if this version is less than (older than) another version"""
        if not isinstance(other, Version):
            return NotImplemented
        return (self.major, self.minor, self.build) < (
            other.major,
            other.minor,
            other.build,
        )

    def __le__(self, other) -> bool:
        """Check if this version is less than or equal to another version"""
        if not isinstance(other, Version):
            return NotImplemented
        return (self.major, self.minor, self.build) <= (
            other.major,
            other.minor,
            other.build,
        )

    def __gt__(self, other) -> bool:
        """Check if this version is greater than (newer than) another version"""
        if not isinstance(other, Version):
            return NotImplemented
        return (self.major, self.minor, self.build) > (
            other.major,
            other.minor,
            other.build,
        )

    def __ge__(self, other) -> bool:
        """Check if this version is greater than or equal to another version"""
        if not isinstance(other, Version):
            return NotImplemented
        return (self.major, self.minor, self.build) >= (
            other.major,
            other.minor,
            other.build,
        )

    def is_newer_than(self, other) -> bool:
        """Check if this version is newer than another version"""
        return self > other


@dataclass
class KeyInfo:
    """
    KeyInfo
    Description: Information related to signing keys in the report
    """

    author_key_en: bool  # Bit 0: Author key enabled
    mask_chip_key: bool  # Bit 1: Mask chip key
    signing_key: int  # Bits 4:2: Signing key (0=VCEK, 1=VLEK, 7=NONE)

    @classmethod
    def from_u32(cls, value: int) -> "KeyInfo":
        """Create KeyInfo from a 32-bit integer"""
        return cls(
            author_key_en=bool(value & 0x1),
            mask_chip_key=bool(value & 0x2),
            signing_key=(value >> 2) & 0x7,
        )

    def to_u32(self) -> int:
        """Convert KeyInfo to a 32-bit integer"""
        result = 0
        if self.author_key_en:
            result |= 0x1
        if self.mask_chip_key:
            result |= 0x2
        result |= (self.signing_key & 0x7) << 2
        return result

    def signing_key_name(self) -> str:
        """Get the name of the signing key"""
        key_names = {0: "vcek", 1: "vlek", 7: "none"}
        return key_names.get(self.signing_key, "reserved")


@dataclass
class TcbVersion:
    """
    TcbVersion
    Description: Represents the Trusted Computing Base (TCB) version information

    Turin and later architectures include an FMC field, while Genoa and Milan do not.
    """

    bootloader: int
    tee: int
    _reserved: bytes
    snp: int
    microcode: int
    fmc: Optional[int] = None  # For Turin+ architectures

    def to_bytes(self) -> bytes:
        """
        Convert TcbVersion to its binary representation.
        Format depends on whether FMC field is present (Turin vs Genoa/Milan).
        Both formats are 8 bytes total.
        """
        if self.fmc is not None:
            # Turin format: FMC (7:0), Bootloader (15:8), TEE (23:16), SNP (31:24), Reserved (55:32), Microcode (63:56)
            return struct.pack(
                "<BBBB3sB",
                self.fmc,
                self.bootloader,
                self.tee,
                self.snp,
                self._reserved,
                self.microcode,
            )
        else:
            # Genoa/Milan format: Bootloader (7:0), TEE (15:8), Reserved (47:16), SNP (55:48), Microcode (63:56)
            return struct.pack(
                "<BB4sBB",
                self.bootloader,
                self.tee,
                self._reserved,
                self.snp,
                self.microcode,
            )

    @classmethod
    def from_bytes(cls, data: bytes, fmc_supported: bool) -> "TcbVersion":
        """
        Create TcbVersion from binary data.

        Args:
            data: 8 bytes of TCB data
            fmc_supported: Whether FMC field is supported
        """
        if fmc_supported:
            # Turin+ format: FMC (7:0), Bootloader (15:8), TEE (23:16), SNP (31:24), Reserved (55:32), Microcode (63:56)
            tcb_data = struct.unpack("<BBBB3sB", data)
            return cls(
                fmc=tcb_data[0],
                bootloader=tcb_data[1],
                tee=tcb_data[2],
                snp=tcb_data[3],
                _reserved=tcb_data[4],
                microcode=tcb_data[5],
            )
        else:
            # Genoa/Milan format: Bootloader (7:0), TEE (15:8), Reserved (47:16), SNP (55:48), Microcode (63:56)
            tcb_data = struct.unpack("<BB4sBB", data)
            return cls(
                bootloader=tcb_data[0],
                tee=tcb_data[1],
                _reserved=tcb_data[2],
                snp=tcb_data[3],
                microcode=tcb_data[4],
                fmc=None,
            )


@dataclass
class Cpuid:
    """
    Cpuid
    Description: Represents CPUID information from the attestation report
    """

    family_id: Optional[
        int
    ] = None  # CPUID_FAM_ID - Combined Extended Family ID and Family ID
    model_id: Optional[
        int
    ] = None  # CPUID_MOD_ID - Model (combined Extended Model and Model fields)
    stepping: Optional[int] = None  # CPUID_STEP - Stepping


@dataclass
class AttestationReport:
    """
    AttestationReport
    Description: Represents an AMD SEV-SNP Attestation Report
    Supports up to version 5 of the attestation report format
    """

    version: int
    guest_svn: int
    policy: GuestPolicy
    family_id: bytes
    image_id: bytes
    vmpl: int
    signature_algo: int
    current_tcb: TcbVersion
    platform_info: PlatformInfo
    key_info: KeyInfo
    report_data: bytes
    measurement: bytes
    host_data: bytes
    id_key_digest: bytes
    author_key_digest: bytes
    report_id: bytes
    report_id_ma: bytes
    reported_tcb: TcbVersion

    # Optional fields added in V3+
    cpuid: Optional[Cpuid] = None

    chip_id: bytes = None
    committed_tcb: TcbVersion = None
    current_version: Version = None
    committed_version: Version = None
    launch_tcb: TcbVersion = None

    # Optional fields added in V5+
    launch_mit_vector: Optional[bytes] = None
    current_mit_vector: Optional[bytes] = None

    signature: Signature = None

    @property
    def supports_cpuid(self) -> bool:
        """Check if this report version supports CPUID fields"""
        return self.version >= 3

    @property
    def supports_tcb_fmc(self) -> bool:
        """Check if this report version supports TCB FMC field"""
        if self.supports_cpuid:
            return self.cpuid.family_id >= 26
        return False

    @property
    def supports_mitigation_vectors(self) -> bool:
        """Check if this report version supports mitigation vector fields"""
        return self.version >= 5

    def get_hwid(self) -> str:
        """
        get_hwid
        Description: Get the hardware ID (HWID) string for the attestation report
        Input: None
        Output: str: HWID hex string
        """
        # hwID is only 8 octets for Turin+ architectures
        if self.supports_tcb_fmc:
            return self.chip_id[:8].hex()
        # hwID is full 64 octets for Genoa/Milan/Siena architectures
        return self.chip_id.hex()

    def to_bytes(self) -> bytes:
        """
        to_bytes
        Description: Convert the AttestationReport to its binary representation
        Input: None
        Output: bytes: Binary representation of the AttestationReport
        """
        # Common fields for all versions
        data = b""
        data += struct.pack("<I", self.version)
        data += struct.pack("<I", self.guest_svn)
        data += struct.pack("<Q", self.policy._value)
        data += self.family_id
        data += self.image_id
        data += struct.pack("<I", self.vmpl)
        data += struct.pack("<I", self.signature_algo)
        data += self.current_tcb.to_bytes()
        data += struct.pack("<Q", self.platform_info._value)
        data += struct.pack("<I", self.key_info.to_u32())
        data += b"\x00\x00\x00\x00"  # reserved
        data += self.report_data
        data += self.measurement
        data += self.host_data
        data += self.id_key_digest
        data += self.author_key_digest
        data += self.report_id
        data += self.report_id_ma
        data += self.reported_tcb.to_bytes()

        # Add CPUID fields for V3+ or padding for V2
        if not self.supports_cpuid:
            # V2 doesn't have CPUID fields, add 24 bytes of padding
            data += b"\x00" * 24
        else:
            # V3+ has CPUID fields
            data += struct.pack(
                "<BBB",
                self.cpuid.family_id if self.cpuid and self.cpuid.family_id else 0,
                self.cpuid.model_id if self.cpuid and self.cpuid.model_id else 0,
                self.cpuid.stepping if self.cpuid and self.cpuid.stepping else 0,
            )
            data += b"\x00" * 21  # reserved

        # Add remaining common fields
        data += self.chip_id
        data += self.committed_tcb.to_bytes()
        data += struct.pack(
            "<BBBBBBBB",
            self.current_version.build,
            self.current_version.minor,
            self.current_version.major,
            0,  # reserved
            self.committed_version.build,
            self.committed_version.minor,
            self.committed_version.major,
            0,
        )  # reserved
        data += self.launch_tcb.to_bytes()

        # Add mitigation vector fields for V5 or padding for V2/V3
        if self.supports_mitigation_vectors:
            # V5 has mitigation vector fields
            data += self.launch_mit_vector
            data += self.current_mit_vector
            data += b"\x00" * 152  # reserved
        else:
            # V2/V3 doesn't have mitigation vectors, add 168 bytes of padding
            data += b"\x00" * 168

        # Add signature
        data += self.signature.to_bytes()

        return data

    @classmethod
    def unpack(cls, binary_data):
        """
        unpack
        Description: Create an AttestationReport instance from binary data with version-aware parsing
        Inputs:
            binary_data: bytes: Binary representation of an AttestationReport
        Output: AttestationReport: An instance of AttestationReport
        """
        logger.debug(f"Unpacking attestation report from {len(binary_data)} bytes")

        if len(binary_data) != 1184:
            raise ValueError(
                f"Invalid attestation report length: {len(binary_data)}, expected 1184"
            )

        # Parse common header to determine version
        offset = 0
        version = struct.unpack("<I", binary_data[offset : offset + 4])[0]
        offset += 4

        logger.debug(f"Detected attestation report version: {version}")

        # Parse common fields (same for all versions)
        guest_svn = struct.unpack("<I", binary_data[offset : offset + 4])[0]
        offset += 4

        policy_value = struct.unpack("<Q", binary_data[offset : offset + 8])[0]
        policy = GuestPolicy(policy_value)
        offset += 8

        family_id = binary_data[offset : offset + 16]
        offset += 16

        image_id = binary_data[offset : offset + 16]
        offset += 16

        vmpl = struct.unpack("<I", binary_data[offset : offset + 4])[0]
        offset += 4

        signature_algo = struct.unpack("<I", binary_data[offset : offset + 4])[0]
        offset += 4

        # Store current TCB binary data for later parsing (after CPUID is available)
        current_tcb_data = binary_data[offset : offset + 8]
        offset += 8

        platform_info_value = struct.unpack("<Q", binary_data[offset : offset + 8])[0]
        platform_info = PlatformInfo(platform_info_value)
        offset += 8

        key_info_value = struct.unpack("<I", binary_data[offset : offset + 4])[0]
        key_info = KeyInfo.from_u32(key_info_value)
        offset += 4

        # Skip reserved field
        offset += 4

        report_data = binary_data[offset : offset + 64]
        offset += 64

        measurement = binary_data[offset : offset + 48]
        offset += 48

        host_data = binary_data[offset : offset + 32]
        offset += 32

        id_key_digest = binary_data[offset : offset + 48]
        offset += 48

        author_key_digest = binary_data[offset : offset + 48]
        offset += 48

        report_id = binary_data[offset : offset + 32]
        offset += 32

        report_id_ma = binary_data[offset : offset + 32]
        offset += 32

        # Store reported TCB binary data for later parsing
        reported_tcb_data = binary_data[offset : offset + 8]
        offset += 8

        # Parse CPUID fields (version-dependent)
        cpuid = None

        if version <= 2:
            # V2 and earlier doesn't have CPUID fields, skip 24 bytes
            offset += 24
        else:
            # V3+ has CPUID fields
            cpuid_data = struct.unpack("<BBB21s", binary_data[offset : offset + 24])
            cpuid_family_id = cpuid_data[0]
            cpuid_model_id = cpuid_data[1]
            cpuid_stepping = cpuid_data[2]

            cpuid = Cpuid(
                family_id=cpuid_family_id,
                model_id=cpuid_model_id,
                stepping=cpuid_stepping,
            )
            offset += 24

        chip_id = binary_data[offset : offset + 64]
        offset += 64

        # Store committed TCB binary data for later parsing
        committed_tcb_data = binary_data[offset : offset + 8]
        offset += 8

        # Parse version fields
        version_data = struct.unpack("<BBBBBBBB", binary_data[offset : offset + 8])
        current_version = Version(
            version_data[2], version_data[1], version_data[0]
        )  # major, minor, build
        committed_version = Version(version_data[6], version_data[5], version_data[4])
        offset += 8

        # Store launch TCB binary data for later parsing
        launch_tcb_data = binary_data[offset : offset + 8]
        offset += 8

        # Parse mitigation vectors (version-dependent)
        launch_mit_vector = None
        current_mit_vector = None

        if version >= 5:
            launch_mit_vector = binary_data[offset : offset + 8]
            current_mit_vector = binary_data[offset + 8 : offset + 16]
            offset += 168
        else:
            # Earlier versions don't have mitigation vectors, skip 168 bytes
            offset += 168

        # Parse signature
        signature_data = binary_data[offset : offset + 512]
        signature = Signature.from_bytes(signature_data)

        # Now that we have CPUID, determine if FMC is supported and parse all TCB data
        fmc_supported = version >= 3 and cpuid.family_id >= 26

        current_tcb = TcbVersion.from_bytes(current_tcb_data, fmc_supported)
        reported_tcb = TcbVersion.from_bytes(reported_tcb_data, fmc_supported)
        committed_tcb = TcbVersion.from_bytes(committed_tcb_data, fmc_supported)
        launch_tcb = TcbVersion.from_bytes(launch_tcb_data, fmc_supported)

        # Create and return the AttestationReport instance
        report = cls(
            version=version,
            guest_svn=guest_svn,
            policy=policy,
            family_id=family_id,
            image_id=image_id,
            vmpl=vmpl,
            signature_algo=signature_algo,
            current_tcb=current_tcb,
            platform_info=platform_info,
            key_info=key_info,
            report_data=report_data,
            measurement=measurement,
            host_data=host_data,
            id_key_digest=id_key_digest,
            author_key_digest=author_key_digest,
            report_id=report_id,
            report_id_ma=report_id_ma,
            reported_tcb=reported_tcb,
            cpuid=cpuid,
            chip_id=chip_id,
            committed_tcb=committed_tcb,
            current_version=current_version,
            committed_version=committed_version,
            launch_tcb=launch_tcb,
            launch_mit_vector=launch_mit_vector,
            current_mit_vector=current_mit_vector,
            signature=signature,
        )

        logger.info(
            f"Successfully parsed attestation report (version: {report.version}, measurement: {report.measurement.hex()})"
        )
        return report

    def log_details(self):
        """
        log_details
        Description: Log a detailed representation of the AttestationReport
        Input: None
        Output: None (logs to logger)
        """
        logger.info("Attestation Report Details:")
        logger.info(f"Version:                     {self.version}")
        logger.info(f"Guest SVN:                   {self.guest_svn}")

        logger.info("Guest Policy:")
        logger.info(f"  ABI Minor:                 {self.policy.abi_minor}")
        logger.info(f"  ABI Major:                 {self.policy.abi_major}")
        logger.info(f"  SMT Allowed:               {self.policy.smt_allowed}")
        logger.info(f"  Migrate MA Allowed:        {self.policy.migrate_ma_allowed}")
        logger.info(f"  Debug Allowed:             {self.policy.debug_allowed}")
        logger.info(
            f"  Single Socket Required:    {self.policy.single_socket_required}"
        )
        logger.info(f"  CXL Allowed:               {self.policy.cxl_allowed}")
        logger.info(f"  MEM AES 256 XTS:           {self.policy.mem_aes_256_xts}")
        logger.info(f"  RAPL Disabled:             {self.policy.rapl_dis}")
        logger.info(f"  Ciphertext Hiding:         {self.policy.ciphertext_hiding}")
        logger.info(f"  Page Swap Disabled:        {self.policy.page_swap_disable}")

        logger.info(f"Family ID:                   {self.family_id.hex()}")
        logger.info(f"Image ID:                    {self.image_id.hex()}")
        logger.info(f"VMPL:                        {self.vmpl}")
        logger.info(f"Signature Algorithm:         {self.signature_algo}")

        logger.info("Current TCB:")
        if self.supports_tcb_fmc:
            logger.info(f"  FMC:                       {self.current_tcb.fmc}")
        logger.info(f"  Bootloader:                {self.current_tcb.bootloader}")
        logger.info(f"  TEE:                       {self.current_tcb.tee}")
        logger.info(f"  Reserved:                  {self.current_tcb._reserved.hex()}")
        logger.info(f"  SNP:                       {self.current_tcb.snp}")
        logger.info(f"  Microcode:                 {self.current_tcb.microcode}")

        logger.info("Platform Info:")
        logger.info(f"  SMT Enabled:               {self.platform_info.smt_enabled}")
        logger.info(f"  TSME Enabled:              {self.platform_info.tsme_enabled}")
        logger.info(f"  ECC Enabled:               {self.platform_info.ecc_enabled}")
        logger.info(f"  RAPL Disabled:             {self.platform_info.rapl_disabled}")
        logger.info(
            f"  Ciphertext Hiding Enabled: {self.platform_info.ciphertext_hiding_enabled}"
        )
        logger.info(
            f"  Alias Check Complete:      {self.platform_info.alias_check_complete}"
        )
        logger.info(f"  TIO Enabled:               {self.platform_info.tio_enabled}")

        logger.info("Key Info:")
        logger.info(f"  Author Key Enabled:        {self.key_info.author_key_en}")
        logger.info(f"  Mask Chip Key:             {self.key_info.mask_chip_key}")
        logger.info(f"  Signing Key:               {self.key_info.signing_key_name()}")

        logger.info(f"Report Data:                 {self.report_data.hex()}")
        logger.info(f"Measurement:                 {self.measurement.hex()}")
        logger.info(f"Host Data:                   {self.host_data.hex()}")
        logger.info(f"ID Key Digest:               {self.id_key_digest.hex()}")
        logger.info(f"Author Key Digest:           {self.author_key_digest.hex()}")
        logger.info(f"Report ID:                   {self.report_id.hex()}")
        logger.info(f"Report ID Migration Agent:   {self.report_id_ma.hex()}")

        logger.info("Reported TCB:")
        if self.supports_tcb_fmc:
            logger.info(f"  FMC:                       {self.reported_tcb.fmc}")
        logger.info(f"  Bootloader:                {self.reported_tcb.bootloader}")
        logger.info(f"  TEE:                       {self.reported_tcb.tee}")
        logger.info(f"  Reserved:                  {self.reported_tcb._reserved.hex()}")
        logger.info(f"  SNP:                       {self.reported_tcb.snp}")
        logger.info(f"  Microcode:                 {self.reported_tcb.microcode}")

        # CPUID fields (V3+ only)
        if self.supports_cpuid:
            if self.cpuid:
                logger.info("CPUID:")
                logger.info(
                    f"  Family ID:                 {self.cpuid.family_id or 'None'}"
                )
                logger.info(
                    f"  Model ID:                  {self.cpuid.model_id or 'None'}"
                )
                logger.info(
                    f"  Stepping:                  {self.cpuid.stepping or 'None'}"
                )
            else:
                logger.info("CPUID:                       Not present")
        else:
            logger.info("CPUID:                       Not supported in V2")

        logger.info(
            f"Chip ID:                     {self.chip_id.hex() if self.chip_id else 'None'}"
        )

        if self.committed_tcb:
            logger.info("Committed TCB:")
            if self.supports_tcb_fmc:
                logger.info(f"  FMC:                       {self.committed_tcb.fmc}")
            logger.info(f"  Bootloader:                {self.committed_tcb.bootloader}")
            logger.info(f"  TEE:                       {self.committed_tcb.tee}")
            logger.info(
                f"  Reserved:                  {self.committed_tcb._reserved.hex()}"
            )
            logger.info(f"  SNP:                       {self.committed_tcb.snp}")
            logger.info(f"  Microcode:                 {self.committed_tcb.microcode}")

        if self.current_version:
            logger.info(f"Current Version:             {self.current_version}")
        if self.committed_version:
            logger.info(f"Committed Version:           {self.committed_version}")

        if self.launch_tcb:
            logger.info("Launch TCB:")
            if self.supports_tcb_fmc:
                logger.info(f"  FMC:                       {self.launch_tcb.fmc}")
            logger.info(f"  Bootloader:                {self.launch_tcb.bootloader}")
            logger.info(f"  TEE:                       {self.launch_tcb.tee}")
            logger.info(
                f"  Reserved:                  {self.launch_tcb._reserved.hex()}"
            )
            logger.info(f"  SNP:                       {self.launch_tcb.snp}")
            logger.info(f"  Microcode:                 {self.launch_tcb.microcode}")

        # Mitigation vector fields (V5+ only)
        if self.supports_mitigation_vectors:
            logger.info(f"Launch Mitigation Vector:    {self.launch_mit_vector.hex()}")
            logger.info(f"Current Mitigation Vector:   {self.current_mit_vector.hex()}")
        else:
            logger.info("Mitigation Vectors:          Not supported in this version")

        if self.signature:
            logger.info("Signature:")
            logger.info(f"  R component:               {self.signature.get_r().hex()}")
            logger.info(f"  S component:               {self.signature.get_s().hex()}")
