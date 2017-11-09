from setuptools import setup

setup(
    name='honeyhornet',
    version='1.0',
    packages=['honeyhornet'],
    url='https://github.com/ajackal/honey-hornet.git',
    license='GNU General Public License v3.0',
    author='Chris Miller',
    author_email='ajackal244@gmail.com',
    description='port scanner & credential tester',
    install_requires=['python-nmap', 'termcolor', 'PyYAML', 'pexpect'],
    scripts=['build_config.py']
)
