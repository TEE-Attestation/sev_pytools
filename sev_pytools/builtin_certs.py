# Copyright 2026 Hewlett Packard Enterprise Development LP.
# SPDX-License-Identifier: MIT
#
# Built-in AMD SEV-SNP certificate authorities.
#
# The AMD Root Key (ARK) and AMD SEV Signing Key (ASK) for each processor
# family are embedded in sev_pytools/amd_certs/<family>.py. Pinning them here
# means the trust anchor no longer depends on what the KDS happens to serve at
# verification time, and that only the per-chip VCEK ever needs to be fetched.

from functools import lru_cache
from typing import Dict, Optional, Union

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from .amd_certs import genoa, milan, turin
from .fetch import ProcType
from .sev_logging import get_logger

logger = get_logger(__name__)

# One chain per KDS certificate-chain name; ProcType.to_kds_url() maps
# Bergamo and Siena onto Genoa.
_CHAINS = {
    ProcType.MILAN.to_kds_url(): milan,
    ProcType.GENOA.to_kds_url(): genoa,
    ProcType.TURIN.to_kds_url(): turin,
}


def _chain_name(processor_model: Union[ProcType, str]) -> str:
    if not isinstance(processor_model, ProcType):
        try:
            processor_model = ProcType[str(processor_model).upper()]
        except KeyError:
            raise ValueError(
                f"Unknown processor model '{processor_model}'. "
                f"Known models: {', '.join(p.name for p in ProcType)}"
            ) from None
    name = processor_model.to_kds_url()
    if name not in _CHAINS:
        raise ValueError(f"No built-in AMD certificates for {processor_model}.")
    return name


@lru_cache(maxsize=None)
def _load(chain_name: str, cert_type: str) -> x509.Certificate:
    pem = getattr(_CHAINS[chain_name], cert_type.upper())
    return x509.load_pem_x509_certificate(pem.encode("ascii"))


def builtin_ark(processor_model: Union[ProcType, str]) -> x509.Certificate:
    """Return the built-in AMD Root Key certificate for the processor's family."""
    return _load(_chain_name(processor_model), "ark")


def builtin_ask(processor_model: Union[ProcType, str]) -> x509.Certificate:
    """Return the built-in AMD SEV Signing Key certificate for the processor's family."""
    return _load(_chain_name(processor_model), "ask")


def builtin_ca(processor_model: Union[ProcType, str]) -> Dict[str, x509.Certificate]:
    """
    builtin_ca
    Description: Built-in CA certificates in the layout used by load_certificates
    Input: processor_model: ProcType (or its name, e.g. "genoa")
    Output: dict: {"ark": x509.Certificate, "ask": x509.Certificate}
    """
    name = _chain_name(processor_model)
    logger.debug(f"Using built-in AMD ARK/ASK for {name}")
    return {"ark": _load(name, "ark"), "ask": _load(name, "ask")}


def builtin_chains() -> Dict[str, Dict[str, x509.Certificate]]:
    """All built-in chains keyed by KDS family name, e.g. {"Genoa": {"ark": ..., "ask": ...}}."""
    return {
        name: {"ark": _load(name, "ark"), "ask": _load(name, "ask")} for name in _CHAINS
    }


def is_builtin_ark(
    cert: x509.Certificate, processor_model: Union[ProcType, str, None] = None
) -> bool:
    """
    is_builtin_ark
    Description: Check that a certificate is byte-for-byte one of the pinned AMD
                 root certificates (the processor family's ARK, or any family's
                 if the processor model is unknown)
    Inputs:
        cert: x509.Certificate (ARK obtained from a certs directory, the KDS or
              the hypervisor's certificate table)
        processor_model: ProcType or its name (optional)
    Output: bool
    """
    if processor_model is None:
        return builtin_family_of_ark(cert) is not None
    der = cert.public_bytes(serialization.Encoding.DER)
    ark = _load(_chain_name(processor_model), "ark")
    return ark.public_bytes(serialization.Encoding.DER) == der


def builtin_family_of_ark(cert: x509.Certificate) -> Optional[str]:
    """Return the KDS family name ("Milan", "Genoa", "Turin") whose pinned ARK matches, else None."""
    der = cert.public_bytes(serialization.Encoding.DER)
    for name in _CHAINS:
        if _load(name, "ark").public_bytes(serialization.Encoding.DER) == der:
            return name
    return None
