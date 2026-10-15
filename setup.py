"""
BlackSentinel Strike - Penetration Testing Suite
Copyright (c) 2024-2025 BlackSentinel Strike - All Rights Reserved
Author: BlackSentinel Strike
License: Proprietary - All Rights Reserved
"""

from setuptools import setup, find_packages

setup(
    name="blacksentinel-strike",
    version="4.1.0",
    author="BlackSentinel Strike",
    description="Advanced Penetration Testing GUI Framework - BlackSentinel Strike",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    packages=find_packages(exclude=["tests", "tests.*"]),
    python_requires=">=3.10",
    install_requires=[
        line.strip()
        for line in open("requirements.txt")
        if line.strip() and not line.startswith("#")
    ],
    entry_points={
        "console_scripts": [
            "blacksentinel-strike=app:main",
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "License :: Proprietary :: All Rights Reserved",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Programming Language :: Python :: 3.13",
    ],
)
