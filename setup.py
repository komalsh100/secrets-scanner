from setuptools import setup, find_packages

setup(
    name="secrets-scanner",
    version="1.0.0",
    author="Komal Sharma",
    description="CLI tool to detect hardcoded secrets and high-entropy strings in codebases and git history",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    packages=find_packages(),
    python_requires=">=3.8",
    entry_points={
        "console_scripts": [
            "secrets-scanner=secrets_scanner.cli:main",
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "Topic :: Security",
        "Topic :: Software Development :: Quality Assurance",
    ],
)
