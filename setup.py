from setuptools import setup

__version__ = '0.0.7'
setup(
        name='capstone_wrapper',
        version=__version__,
        description='A functional wrapper for capstone Python',
        url='',
        author='Chris Coetzee',
        author_email='chriscz93@gmail.com',
        license='Apache 2.0',
        packages=['capstone_wrapper'],
        install_requires=['capstone'],
        zip_safe=False
)
