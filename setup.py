from setuptools import setup

__version__ = '0.2.2'
setup(
        name='capstone_wrapper',
        version=__version__,
        description='A functional wrapper for capstone Python',
        url='',
        author='Chris Coetzee',
        author_email='chriscz93@gmail.com',
        license='Mozilla Public License 2.0 (MPL 2.0)',
        packages=['capstone_wrapper'],
#        install_requires=['capstone >= 3.0.3'],
        zip_safe=False
)
