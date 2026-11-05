#!/usr/bin/env python3
"""
OpenIronKey - Setup Script
"""

from setuptools import setup, find_packages
import os

# Read version
VERSION = "1.0.0"

# Read long description
with open("README.md", "r", encoding="utf-8") as f:
    long_description = f.read()

# Requirements
install_requires = [
    # Core: only stdlib (ctypes, array, hashlib, etc.)
]

extras_require = {
    'gui': [
        'pygobject>=3.42',
    ],
    'pkcs11': [
        'python-pkcs11>=0.9',
    ],
    'dev': [
        'pytest>=7.0',
        'black>=23.0',
        'mypy>=1.0',
        'pre-commit>=3.0',
    ],
}

setup(
    name="openironkey",
    version=VERSION,
    author="OpenIronKey Contributors",
    author_email="",
    description="Modern Linux toolkit for IronKey S200 secure USB drives",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/openironkey",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: MIT License",
        "Operating System :: POSIX :: Linux",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security",
        "Topic :: System :: Hardware",
        "Topic :: Security :: Cryptography",
    ],
    python_requires=">=3.10",
    install_requires=install_requires,
    extras_require=extras_require,
    entry_points={
        "console_scripts": [
            "openironkey = openironkey.cli.ironkey_cli:main",
            "openironkey-applet = openironkey.applet.ironkey_applet:main",
            "openironkey-gui = openironkey.gui.ironkey_gui:main",
        ],
    },
    include_package_data=True,
    package_data={
        "": ["*.md", "*.txt"],
    },
)