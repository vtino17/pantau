from distutils.core import setup

setup(
    name="pantau",
    version="0.1.0",
    description="CLI inspeksi keamanan link & domain",
    packages=["pantau"],
    entry_points={
        "console_scripts": ["pantau = pantau.cli:main"],
    },
)
