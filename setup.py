#!/usr/bin/env python3
#
# setup.py

from setuptools import setup, find_packages

# Read the requirements from a separate requirements.txt file if needed
with open("requirements.txt") as f:
    required = f.read().splitlines()

setup(
    name="sshive",
    version="0.1.0",
    description="A simple SSH honeypot to log login attempts",
    author="Your Name",
    author_email="woodyk@gmail.com",
    url="https://github.com/woodyk/sshive",
    packages=find_packages(),
    entry_points={
        "console_scripts": [
            "sshive=sshive.main:main",  # Now points to main.py
        ]
    },
    install_requires=required,
    classifiers=[
        "Programming Language :: Python :: 3",
        "Operating System :: OS Independent",
        "License :: OSI Approved :: MIT License",
        "Topic :: Security",
    ],
    python_requires=">=3.6",
    include_package_data=True,
    zip_safe=False,
)
