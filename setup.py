from setuptools import setup, find_packages

setup(
    name="napalm-hios",
    version="2.0.0",
    packages=find_packages(),
    description="NAPALM driver for HiOS network switches by Belden",
    author="Adam Rickards",
    author_email="adam_rickards@hotmail.com",
    url="https://github.com/AdamRickards/napalm-hios",
    install_requires=[
        "crude-engine>=2.9.0",
        "napalm>=3.0.0",
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
