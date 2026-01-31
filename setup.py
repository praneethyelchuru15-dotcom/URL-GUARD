from setuptools import setup

setup(
    name="url-guard",
    version="1.0.0",
    description="A comprehensive network security scanning tool.",
    author="Antigravity",
    py_modules=["main"],
    install_requires=[
        "requests",
        "beautifulsoup4",
        "python-whois",
    ],
    entry_points={
        "console_scripts": [
            "url-guard=main:main",
        ],
    },
)
