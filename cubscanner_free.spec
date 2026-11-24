# -*- mode: python ; coding: utf-8 -*-
block_cipher = None

a = Analysis(
    ['cubscanner_free.py'],
    pathex=[],
    binaries=[],
    # Inclui as imagens (logo e icone) dentro do executável
    datas=[('logo.png', '.'), ('icon.ico', '.')], 
    hiddenimports=[
        'scapy.all', 
        'psutil', 
        'winreg', 
        'npcap_setup', 
        'pysnmp.hlapi', 
        'csv' # Força a inclusão do CSV
    ],
    hookspath=[],
    runtime_hooks=[],
    # Exclui APENAS o que é do PRO (IA, WiFi, Banco de dados, etc)
    excludes=[
        'llama_cpp', 
        'wifi_monitor', 
        'sqlite3', 
        'matplotlib', 
        'pandas.tests', 
        'numpy.tests'
    ],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='CubScannerFree',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=False,
    icon='icon.ico' # Usa o ícone na barra de tarefas
)