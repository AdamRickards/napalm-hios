from setuptools import setup, find_packages

setup(
    name="napalm-hios",
    version="0.1.0",
    packages=find_packages(),
    description="NAPALM driver for HiOS network switches by Belden",
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
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires='>=3.7',
)
