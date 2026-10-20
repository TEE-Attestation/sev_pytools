# Copyright 2025 Hewlett Packard Enterprise Development LP.
# SPDX-License-Identifier: MIT
#
# Setup configuration for sev_pytools package.

from setuptools import find_packages, setup

setup(
    name="sev_pytools",
    version="0.6.0",
    packages=find_packages(),
    install_requires=[
        "requests",
        "cryptography>=39.0.0",
    ],
    entry_points={
        "console_scripts": [
            "sev-fetch=sev_pytools.fetch:main",
            "sev-print=sev_pytools.print_report:main",
            "sev-verify=sev_pytools.verify:main",
        ],
    },
    description="Python tools for AMD SEV-SNP attestation",
    url="https://github.com/TEE-Attestation/sev_pytools",
    author="Isaac Matthews",
    author_email="isaac@hpe.com",
    license="MIT",
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
    ],
)
