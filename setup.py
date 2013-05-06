from distutils.core import setup

setup(
    name='hdwallet',
    version='0.2',
    packages=['hdwallet'],
    license='MIT',
    author='Felix Weis',
    author_email='mail@felixweis.com',
    url='https://github.com/felixweis/hdwallet',
    description='Secure, hierarchical Bitcoin wallet generation',
    install_requires=['ecdsa==0.8']
)