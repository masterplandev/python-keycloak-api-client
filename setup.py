from setuptools import setup


with open('README.md', 'r') as readme:
    long_description = readme.read()

setup(
    name='python-keycloak-api-client',
    version='0.5.0',
    description='Client for Keycloak Api (mostly users and impersonation)',
    keywords='keycloak,client,api',
    long_description=long_description,
    long_description_content_type='text/markdown',
    author='Szymon Marcinkowski',
    author_email='szymon@masterhub.com',
    license='MIT',
    url='https://github.com/masterplandev/python-keycloak-api-client',
    packages=['keycloak_api_client'],
    classifiers=[
        'Environment :: Web Environment',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
    ],
    install_requires=[
        'attrs>=19.3',
        'requests>=2.23',
    ],
    extras_require={
        'dev': [
            'pytest>=6.2',
            'flake8>=6.2',
        ]
    }
)
