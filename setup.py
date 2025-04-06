from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="securepass",
    version="1.0.0",
    author="Mathias Vallentin Bech",
    description="A comprehensive password security toolkit",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/MathiasVbech/securepass",
    packages=find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Topic :: Security",
    ],
    python_requires=">=3.6",
    entry_points={
        "console_scripts": [
            "securepass=securepass:main",
        ],
    },
    include_package_data=True,
    package_data={
        "": ["dictionaries/*", "dictionaries/wordlists/*"],
    },
)