from distutils.core import setup

setup(
    name='hdwallet',
    version='0.3',
    packages=['hdwallet'],
    license='MIT',
    author='Felix Weis',
    author_email='mail@felixweis.com',
    url='https://github.com/FelixWeis/python-hdwallet',
    description='Secure, hierarchical Bitcoin wallet generation',
    install_requires=['ecdsa==0.8']
)