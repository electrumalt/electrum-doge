#!/usr/bin/python

# python setup.py sdist --format=zip,gztar

from setuptools import setup
import os
import sys
import platform
import imp


version = imp.load_source('version', 'lib/version.py')
i18n = imp.load_source('i18n', 'lib/i18n.py')
util = imp.load_source('util', 'lib/util.py')

if sys.version_info[:3] < (2, 7, 0):
    sys.exit("Error: Electrum requires Python version >= 2.7.0...")



if (len(sys.argv) > 1) and (sys.argv[1] == "install"): 
    # or (platform.system() != 'Windows' and platform.system() != 'Darwin'):
    print "Including all files"
    data_files = []
    usr_share = util.usr_share_dir()
    if not os.access(usr_share, os.W_OK):
        try:
            os.mkdir(usr_share)
        except:
            sys.exit("Error: cannot write to %s.\nIf you do not have root permissions, you may install Electrum in a virtualenv.\nAlso, please note that you can run Electrum without installing it on your system."%usr_share)

    data_files += [
        (os.path.join(usr_share, 'applications'), ['electrum-doge.desktop']),
        (os.path.join(usr_share, 'app-install', 'icons'), ['icons/electrum-doge.png'])
    ]
    if not os.path.exists('locale'):
        os.mkdir('locale')
    for lang in os.listdir('locale'):
        if os.path.exists('locale/%s/LC_MESSAGES/electrum.mo' % lang):
            data_files.append((os.path.join(usr_share, 'locale/%s/LC_MESSAGES' % lang), ['locale/%s/LC_MESSAGES/electrum.mo' % lang]))


    appdata_dir = os.path.join(usr_share, "electrum-doge")
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
else:
    data_files = []

setup(
    name="Electrum-Doge",
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
        'tlslite',
        'btcutils',
        'ltc_scrypt'
    ],
    package_dir={
        'electrum_doge': 'lib',
        'electrum_doge_gui': 'gui',
        'electrum_doge_plugins': 'plugins',
    },
    scripts=['electrum-doge'],
    data_files=data_files,
    py_modules=[
        'electrum_doge.account',
        'electrum_doge.auxpow',
        'electrum_doge.bitcoin',
        'electrum_doge.blockchain',
        'electrum_doge.bmp',
        'electrum_doge.commands',
        'electrum_doge.daemon',
        'electrum_doge.i18n',
        'electrum_doge.interface',
        'electrum_doge.mnemonic',
        'electrum_doge.msqr',
        'electrum_doge.network',
        'electrum_doge.network_proxy',
        'electrum_doge.old_mnemonic',
        'electrum_doge.paymentrequest',
        'electrum_doge.paymentrequest_pb2',
        'electrum_doge.plugins',
        'electrum_doge.qrscanner',
        'electrum_doge.scrypt',
        'electrum_doge.simple_config',
        'electrum_doge.synchronizer',
        'electrum_doge.transaction',
        'electrum_doge.util',
        'electrum_doge.verifier',
        'electrum_doge.version',
        'electrum_doge.wallet',
        'electrum_doge.x509',
        'electrum_doge_gui.gtk',
        'electrum_doge_gui.qt.__init__',
        'electrum_doge_gui.qt.amountedit',
        'electrum_doge_gui.qt.console',
        'electrum_doge_gui.qt.history_widget',
        'electrum_doge_gui.qt.icons_rc',
        'electrum_doge_gui.qt.installwizard',
        'electrum_doge_gui.qt.lite_window',
        'electrum_doge_gui.qt.main_window',
        'electrum_doge_gui.qt.network_dialog',
        'electrum_doge_gui.qt.password_dialog',
        'electrum_doge_gui.qt.paytoedit',
        'electrum_doge_gui.qt.qrcodewidget',
        'electrum_doge_gui.qt.qrtextedit',
        'electrum_doge_gui.qt.receiving_widget',
        'electrum_doge_gui.qt.seed_dialog',
        'electrum_doge_gui.qt.transaction_dialog',
        'electrum_doge_gui.qt.util',
        'electrum_doge_gui.qt.version_getter',
        'electrum_doge_gui.stdio',
        'electrum_doge_gui.text',
        'electrum_doge_plugins.btchipwallet',
        'electrum_doge_plugins.coinbase_buyback',
        'electrum_doge_plugins.cosigner_pool',
        'electrum_doge_plugins.exchange_rate',
        'electrum_doge_plugins.greenaddress_instant',
        'electrum_doge_plugins.labels',
        'electrum_doge_plugins.trezor',
        'electrum_doge_plugins.virtualkeyboard',
		'electrum_doge_plugins.plot',
    ],
    description="Lightweight Dogecoin Wallet",
    author="Thomas Voegtlin",
    author_email="thomasv1@gmx.de",
    license="GNU GPLv3",
    url="https://electrum-doge.com",
    long_description="""Lightweight Dogecoin Wallet"""
)
