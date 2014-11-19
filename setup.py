#!/usr/bin/python

# python setup.py sdist --format=zip,gztar

from setuptools import setup
import os
import sys
import platform
import imp


version = imp.load_source('version', 'lib/version.py')
util = imp.load_source('util', 'lib/util.py')

if sys.version_info[:3] < (2, 7, 0):
    sys.exit("Error: Electrum requires Python version >= 2.7.0...")

usr_share = util.usr_share_dir()
if not os.access(usr_share, os.W_OK):
    try:
        os.mkdir(usr_share)
    except:
        sys.exit("Error: cannot write to %s.\nIf you do not have root permissions, you may install Electrum-IXC in a virtualenv.\nAlso, please note that you can run Electrum-IXC without installing it on your system."%usr_share)

data_files = []
if (len(sys.argv) > 1 and (sys.argv[1] == "sdist")) or (platform.system() != 'Windows' and platform.system() != 'Darwin'):
    print "Including all files"
    data_files += [
        (os.path.join(usr_share, 'applications/'), ['electrum-ixc.desktop']),
        (os.path.join(usr_share, 'app-install', 'icons/'), ['icons/electrum-ixc.png'])
    ]
    if not os.path.exists('locale'):
        os.mkdir('locale')
    for lang in os.listdir('locale'):
        if os.path.exists('locale/%s/LC_MESSAGES/electrum.mo' % lang):
            data_files.append((os.path.join(usr_share, 'locale/%s/LC_MESSAGES' % lang), ['locale/%s/LC_MESSAGES/electrum.mo' % lang]))

appdata_dir = os.path.join(usr_share, "electrum-ixc")

data_files += [
    (appdata_dir, ["data/README"]),
    (os.path.join(appdata_dir, "cleanlook"), [
        "data/cleanlook/name.cfg",
        "data/cleanlook/style.css"
    ]),
    (os.path.join(appdata_dir, "sahara"), [
        "data/sahara/name.cfg",
        "data/sahara/style.css"
    ]),
    (os.path.join(appdata_dir, "dark"), [
        "data/dark/name.cfg",
        "data/dark/style.css"
    ])
]

for lang in os.listdir('data/wordlist'):
    data_files.append((os.path.join(appdata_dir, 'wordlist'), ['data/wordlist/%s' % lang]))


setup(
    name="Electrum-IXC",
    version=version.ELECTRUM_VERSION,
    install_requires=[
        'slowaes',
        'ecdsa>=0.9',
        'pbkdf2',
        'requests',
        'pyasn1',
        'pyasn1-modules',
        'qrcode',
        'SocksiPy-branch',
        'tlslite'
    ],
    package_dir={
        'electrum': 'lib',
        'electrum_gui': 'gui',
        'electrum_plugins': 'plugins',
    },
    scripts=['electrum'],
    data_files=data_files,
    py_modules=[
        'electrum_ixc.account',
        'electrum_ixc.auxpow',
        'electrum_ixc.bitcoin',
        'electrum_ixc.blockchain',
        'electrum_ixc.bmp',
        'electrum_ixc.commands',
        'electrum_ixc.daemon',
        'electrum_ixc.i18n',
        'electrum_ixc.interface',
        'electrum_ixc.mnemonic',
        'electrum_ixc.msqr',
        'electrum_ixc.network',
        'electrum_ixc.network_proxy',
        'electrum_ixc.old_mnemonic',
        'electrum_ixc.paymentrequest',
        'electrum_ixc.paymentrequest_pb2',
        'electrum_ixc.plugins',
        'electrum_ixc.qrscanner',
        'electrum_ixc.simple_config',
        'electrum_ixc.synchronizer',
        'electrum_ixc.transaction',
        'electrum_ixc.util',
        'electrum_ixc.verifier',
        'electrum_ixc.version',
        'electrum_ixc.wallet',
        'electrum_ixc.x509',
        'electrum_ixc_gui.gtk',
        'electrum_ixc_gui.qt.__init__',
        'electrum_ixc_gui.qt.amountedit',
        'electrum_ixc_gui.qt.console',
        'electrum_ixc_gui.qt.history_widget',
        'electrum_ixc_gui.qt.icons_rc',
        'electrum_ixc_gui.qt.installwizard',
        'electrum_ixc_gui.qt.lite_window',
        'electrum_ixc_gui.qt.main_window',
        'electrum_ixc_gui.qt.network_dialog',
        'electrum_ixc_gui.qt.password_dialog',
        'electrum_ixc_gui.qt.paytoedit',
        'electrum_ixc_gui.qt.qrcodewidget',
        'electrum_ixc_gui.qt.qrtextedit',
        'electrum_ixc_gui.qt.receiving_widget',
        'electrum_ixc_gui.qt.seed_dialog',
        'electrum_ixc_gui.qt.transaction_dialog',
        'electrum_ixc_gui.qt.util',
        'electrum_ixc_gui.qt.version_getter',
        'electrum_ixc_gui.stdio',
        'electrum_ixc_gui.text',
        'electrum_ixc_plugins.btchipwallet',
        'electrum_ixc_plugins.coinbase_buyback',
        'electrum_ixc_plugins.cosigner_pool',
        'electrum_ixc_plugins.exchange_rate',
        'electrum_ixc_plugins.greenaddress_instant',
        'electrum_ixc_plugins.labels',
        'electrum_ixc_plugins.trezor',
        'electrum_ixc_plugins.virtualkeyboard',
		'electrum_plugins.plot',
    ],
    description="Lightweight Ixcoin Wallet",
    author="Thomas Voegtlin",
    author_email="thomasv1@gmx.de",
    license="GNU GPLv3",
    url="https://electrumalt.org",
    long_description="""Lightweight Ixcoin Wallet"""
)
