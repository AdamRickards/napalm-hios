from setuptools import setup, find_packages
from pathlib import Path

# Read the contents of README.md
this_directory = Path(__file__).parent
long_description = (this_directory / "README.md").read_text()

setup(
    name="napalm-hios",
    version="1.0.1",
    packages=find_packages(),
    description="NAPALM driver for HiOS network switches by Belden",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="Your Name",
    author_email="your.email@example.com",
    url="https://github.com/yourusername/napalm-hios",
    install_requires=[
        "napalm>=3.0.0",
        "ncclient>=0.6.9",
        "netmiko>=3.3.0",
        "pysnmp>=4.4.12"
    ],
    entry_points={
        'napalm_drivers': [
            'hios=napalm_hios:HIOSDriver'
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: Apache Software License",
        "Operating System :: OS Independent",
    ],
    python_requires='>=3.7',
)
