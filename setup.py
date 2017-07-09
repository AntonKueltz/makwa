from setuptools import setup, Extension, Command


class TestCommand(Command):
    user_options = []
    description = "Run all tests"

    def initialize_options(self):
        pass

    def finalize_options(self):
        pass

    def run(self):
        from subprocess import call
        call(['python', '-m', 'makwa.test'])


setup(
    name='makwa',
    version='1.0.1',
    author='Anton Kueltz',
    author_email='kueltz.anton@gmail.com',
    keywords='makwa password hashing kdf',
    description='A password hashing function that supports delegation',
    long_description=''.join(open('README.rst', 'r').readlines()),
    url='https://github.com/AntonKueltz/makwa',
    packages=['makwa'],
    cmdclass={'test': TestCommand},
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'Topic :: Security :: Cryptography',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 3',
    ],
)
