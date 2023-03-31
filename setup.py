import setuptools

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setuptools.setup(
    name="authproxy",
    version="0.0.0",
    author="Ismael Raya",
    author_email="phornee@gmail.com",
    description="Reverse proxy with synology authentication",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/Phornee/authproxy",
    packages=setuptools.find_packages(),
    package_data={
        '': ['*.yml'],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Topic :: Home Automation"
    ],
    install_requires=[
        'Flask>=1.1.2',
        'gunicorn>=20.1.0',
        'flask-compress>=1.9.0',
        'importlib-metadata>=4.5.0',
        'tzlocal>=4.1',
    ],
    python_requires='>=3.6',
)
