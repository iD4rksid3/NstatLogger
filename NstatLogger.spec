# -*- mode: python ; coding: utf-8 -*-

block_cipher = None


a = Analysis(['NstatLogger1.1.py'],
             pathex=['C:\\%userprofile%\\Desktop\\NstatLogger'],
             binaries=[],
             datas=[],
             hiddenimports=[],
             hookspath=[],
             runtime_hooks=[],
             excludes=[],
             win_no_prefer_redirects=False,
             win_private_assemblies=False,
             cipher=block_cipher,
             noarchive=False)
pyz = PYZ(a.pure, a.zipped_data,
             cipher=block_cipher)
exe = EXE(pyz,
          a.scripts,
          a.binaries,
          a.zipfiles,
          a.datas,
          [],
          name='NstatLogger',
          debug=False,
          bootloader_ignore_signals=False,
          strip=False,
          upx=True,
          upx_exclude=[],
          runtime_tmpdir=None,
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
          console=True , icon='NstatLogger\\rsrc\\file.ico')

=======
          console=True , icon='rsrc\\file.ico')
>>>>>>> parent of 30e705c... 	modified:   NstatLogger.py
=======
          console=True , icon='rsrc\\file.ico')
>>>>>>> parent of 30e705c... 	modified:   NstatLogger.py
=======
          console=True , icon='rsrc\\file.ico')
>>>>>>> parent of 30e705c... 	modified:   NstatLogger.py
