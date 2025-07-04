#!/usr/bin/env python3
from setuptools import setup, find_packages

setup(
    name="reconx",
    version="1.0.0",
    description="Extended Reconnaissance Tool",
    packages=find_packages(),
    install_requires=[
        "colorama==0.4.6",
        "requests==2.31.0", 
        "dnspython==2.4.2",
        "urllib3==2.0.7"
    ],
    entry_points={
        'console_scripts': [
            'reconx=core:main',
        ],
    },
    python_requires='>=3.6',
) 