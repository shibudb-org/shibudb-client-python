#!/usr/bin/env python3
"""
Setup script for ShibuDb Python Client
"""

from setuptools import setup, find_packages
import os

# Read the README file
def read_readme():
    readme_path = os.path.join(os.path.dirname(__file__), 'README.md')
    if os.path.exists(readme_path):
        with open(readme_path, 'r', encoding='utf-8') as f:
            return f.read()
    return "ShibuDb Python Client - A comprehensive Python client for ShibuDb database"

setup(
    name="shibudb-client",
    version="1.0.0",
    description="A comprehensive Python client for ShibuDb database",
    long_description=read_readme(),
    long_description_content_type="text/markdown",
    author="ShibuDb Team",
    author_email="support@shibudb.com",
    url="https://github.com/Podcopic-Labs/ShibuDb",
    packages=find_packages(),
    py_modules=["shibudb_client"],
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Topic :: Database",
        "Topic :: Software Development :: Libraries :: Python Modules",
    ],
    python_requires=">=3.7",
    install_requires=[
        # No external dependencies required
        # Uses only Python standard library
    ],
    extras_require={
        "dev": [
            "pytest>=6.0",
            "pytest-cov>=2.0",
            "black>=21.0",
            "flake8>=3.8",
            "mypy>=0.800",
        ],
    },
    entry_points={
        "console_scripts": [
            "shibudb-client=shibudb_client:main",
        ],
    },
    keywords="database, key-value, vector, similarity-search, embedded",
    project_urls={
        "Bug Reports": "https://github.com/Podcopic-Labs/ShibuDb/issues",
        "Source": "https://github.com/Podcopic-Labs/ShibuDb",
        "Documentation": "https://github.com/Podcopic-Labs/ShibuDb/tree/main/python_client",
    },
)