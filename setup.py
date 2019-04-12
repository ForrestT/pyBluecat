from setuptools import setup


def readme():
    with open('README.md') as f:
        return f.read()

setup(
        name='proteus',
        version='0.0.1',
        description='Python wrapper around Bluecat APIs',
        long_description=readme(),
        classifiers=[
            'Development Status :: 3 - Alpha',
            'Programming Language :: Python :: 2.7',
            'License :: Freely Distributable',
            'Natural Language :: English',
        ],
    url='https://github.com/ForrestT/pyBluecat',
        author='Forrest Throesch',
        author_email='fmthroesch@gmail.com',
        license='Freely Distributable',
        packages=[
            'proteus',
            'proteus.tools',
            'proteus.data'
        ],
        entry_points={
            'console_scripts': [
                'proteus=proteus.tools.cli:main',
                'proteus-assinv-search=proteus.tools.assinv_search:main',
                'proteus-dhcp-request=proteus.tools.rundeck_dhcp_request:main',
                'proteus-dhcp-bulk-request=proteus.tools.rundeck_dhcp_bulk_request:main',
                'proteus-dhcp-update=proteus.tools.rundeck_dhcp_update:main',
                'proteus-dhcp-delete=proteus.tools.rundeck_dhcp_delete:main',
                'proteus-dhcp-search=proteus.tools.rundeck_dhcp_search:main',
                'proteus-vip-request=proteus.tools.vips:main',
                'proteus-search=proteus.tools.search:main',
                'proteus-network-enumerate=proteus.tools.enumerate_networks:main',
                'proteus-static-request=proteus.tools.static_request:main'
            ]
        },
        scripts=[
            'bin/proteus-dhcp-from-list',
            'bin/proteus-search-mac',
            'bin/proteus-static-delete',
            'bin/proteus-static-from-list',
        ],
        install_requires=[
            'suds',
            'dnspython'
        ],
        zip_safe=False)
