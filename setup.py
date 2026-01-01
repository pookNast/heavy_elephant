#!/usr/bin/env python3
"""
Heavy Elephant - PS5 Security Research Toolkit
"""
from setuptools import setup, find_packages
from pathlib import Path

# Read README for long description
readme_path = Path(__file__).parent / "README.md"
long_description = readme_path.read_text(encoding="utf-8") if readme_path.exists() else ""

setup(
    name="heavy_elephant",
    version="3.0.0",
    author="Heavy Elephant Contributors",
    author_email="",
    description="PS5 Security Research Toolkit",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/heavy_elephant",
    packages=find_packages(exclude=["tests", "tests.*", "docs"]),
    python_requires=">=3.11",
    install_requires=[
        "pycryptodome>=3.19.0",
        "click>=8.1.0",
        "rich>=13.0.0",
    ],
    extras_require={
        "dev": [
            "pytest>=7.0.0",
            "pytest-cov>=4.0.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "ps5-boot-decrypt=tools.ps5_boot_decrypt:main",
            "ps5-pkg-tool=tools.ps5_pkg_tool:cli",
            "ps5-self-tool=tools.ps5_self_tool:cli",
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Intended Audience :: Science/Research",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security :: Cryptography",
        "Topic :: Software Development :: Libraries :: Python Modules",
    ],
    keywords="ps5, security, research, cryptography, firmware",
    project_urls={
        "Bug Reports": "https://github.com/yourusername/heavy_elephant/issues",
        "Source": "https://github.com/yourusername/heavy_elephant",
    },
)
