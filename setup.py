import os

from setuptools import setup, find_packages

req_tests = ["pytest", "pytest-httpserver", "pytest-asyncio"]
req_lint = ["flake8", "flake8-docstrings"]
req_etc = ["black", "isort"]
req_dev = req_tests + req_lint + req_etc

with open(os.path.join('.', 'VERSION')) as version_file:
    version = version_file.read().strip()

with open("README.md", 'r') as f:
    long_description = f.read()

with open("requirements.txt") as requirements:
    requires = list(requirements)

setup_options = {
    'name': 'icon-did-sdk',
    'version': version,
    'description': 'ICON DID SDK for Python is a collection of libraries which allow you to interact '
                   'with a local or remote ICON DID service using an HTTP connection.',
    'long_description': long_description,
    'long_description_content_type': 'text/markdown',
    'author': 'ICONLOOP',
    'author_email': 'foo@icon.foundation',
    'url': 'https://github.com/iconloop/did-sdk-python',
    'packages': find_packages(exclude=['tests*']),
    'install_requires': requires,
    "extras_require": {
        "tests": req_tests,
        "lint": req_lint,
        "dev": req_dev
    },
    'python_requires': '~=3.11',
    'license': 'Apache License 2.0',
    'classifiers': [
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: Developers',
        'Intended Audience :: System Administrators',
        'Natural Language :: English',
        'License :: OSI Approved :: Apache Software License',
        'Programming Language :: Python :: 3.9'
    ]
}

setup(**setup_options)
