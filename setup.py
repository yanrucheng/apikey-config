from setuptools import setup

setup(
    name="apikey-config",
    version="0.1.0",
    py_modules=["apikey", "verify"],
    install_requires=[
        "argon2-cffi>=23.1.0",
    ],
    entry_points={
        "console_scripts": [
            "apikey = apikey:main",
        ],
    },
)
