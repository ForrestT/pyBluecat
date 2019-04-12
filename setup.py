from setuptools import setup


def readme():
    with open('README.md') as f:
        return f.read()

setup(
        name='pybluecat',
        version='0.1.1',
        description='Python wrapper around Bluecat APIs',
        long_description=readme(),
        classifiers=[
            'Development Status :: 3 - Alpha',
            'Programming Language :: Python :: 2.7',
            'Programming Language :: Python :: 3.6',
            'License :: Freely Distributable',
            'Natural Language :: English',
        ],
    url='https://github.com/ForrestT/pyBluecat',
        author='Forrest Throesch',
        author_email='fmthroesch@gmail.com',
        license='Freely Distributable',
        packages=[
            'pybluecat',
            'pybluecat.tools',
            'pybluecat.data'
        ],
        entry_points={
            'console_scripts': [
                'bluecat=pybluecat.tools.cli:main',
                'bluecat-assinv-search=pybluecat.tools.assinv_search:main',
                'bluecat-dhcp-request=pybluecat.tools.rundeck_dhcp_request:main',
                'bluecat-dhcp-bulk-request=pybluecat.tools.rundeck_dhcp_bulk_request:main',
                'bluecat-dhcp-update=pybluecat.tools.rundeck_dhcp_update:main',
                'bluecat-dhcp-delete=pybluecat.tools.rundeck_dhcp_delete:main',
                'bluecat-dhcp-search=pybluecat.tools.rundeck_dhcp_search:main',
                'bluecat-vip-request=pybluecat.tools.vips:main',
                'bluecat-search=pybluecat.tools.search:main',
                'bluecat-network-enumerate=pybluecat.tools.enumerate_networks:main',
                'bluecat-static-request=pybluecat.tools.static_request:main'
            ]
        },
        install_requires=[
            'dnspython'
        ],
        zip_safe=False)
