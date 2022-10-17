# -*- coding: utf-8 -*-
from distutils.core import setup
from setuptools import find_packages

setup(name='checkmate3',
      version='0.2.0',
      author='Andreas Dewes - QuantifiedCode UG (haftungsbeschränkt)',
      author_email='andreas@quantifiedcode.com',
      license='MIT',
install_requires = [
"blitzdb@https://github.com/marcinguy/blitzdb3-ce#egg=blitzdb",
'pylint',
'pyflakes',
'pep8',
'six',
'chardet',
'pyyaml',
'sqlalchemy'
],
      entry_points={
          'console_scripts': [
              'checkmate = checkmate.scripts.manage:main',
          ],
      },
      url='https://github.com/quantifiedcode/checkmate',
      packages=find_packages(),
      zip_safe=False,
      description='A meta-code checker written in Python.',
      long_description="""
Checkmate is a cross-language (meta-)tool for static code analysis, written in Python.
Unlike other tools, it provides a global overview of the code quality in a project and aims
to provide clear, actionable insights to the user.

Documentation
=============

The documentation can be found `here <https://docs.quantifiedcode.com/checkmate>`.

Source Code
===========

The source code can be found on `Github <https://github.com/quantifiedcode/checkmate>`.

Changelog
=========

* 0.2.0: Beta-release
"""
      )
