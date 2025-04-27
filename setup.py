from setuptools import setup, find_packages

setup(
    name="securepip",
    version="0.1.0",
    packages=find_packages(),
    install_requires=[
        "requests>=2.31.0",
        "packaging>=23.2",
        "colorama>=0.4.6",
        "tqdm>=4.66.1",
        "pyyaml>=6.0.1",
    ],
    entry_points={
        "console_scripts": [
            "securepip=securepip.cli:main",
        ],
    },
    author="Patrick Hastings",
    author_email="phastings@openmobo.com",
    description="A security-focused package installer and analyzer for Python",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    url="https://github.com/gnubyte/securepip",
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
    ],
    python_requires=">=3.9",
) 