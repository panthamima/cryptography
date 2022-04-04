# -*- coding: utf-8 -*-
import os, shutil

def makeDir(instance, implementation):
    pathName = instance + '/' + implementation
    try:
        os.makedirs(pathName)
    except OSError:
        pass

def copySourceFiles(instance, implementation, sourceFiles):
    for fileName in sourceFiles:
        shutil.copyfile('../Sources/'+fileName, instance+'/'+implementation+'/'+fileName)

def copyVariantFiles(instance, implementation):
    shutil.copyfile('api-'+instance+'.h', instance+'/'+implementation+'/api.h')
    shutil.copyfile('hash-'+instance+'.c', instance+'/'+implementation+'/hash.c')
    shutil.copyfile('int-set-'+instance+'.h', instance+'/'+implementation+'/KeccakF-1600-int-set.h')

def copyVariantFilesNoWrapper(instance, implementation):
    shutil.copyfile('api-'+instance+'.h', instance+'/'+implementation+'/api.h')

def writeImplementors(instance, implementation, implementors):
    with open(instance+'/'+implementation+'/implementors', 'w') as f:
        for person in implementors:
            f.write(person+'\n')

Ronny = ['Ronny Van Keer']
Designers = ['Guido Bertoni', 'Joan Daemen', 'Michaël Peeters', 'Gilles Van Assche']

def makeOpt64(instance, laneComplementing, unrolling):
    implementation = 'opt64'
    if (laneComplementing):
        implementation = implementation + 'lc'
    implementation = implementation + 'u{0}'.format(unrolling)
    print('  Implementation', implementation)
    makeDir(instance, implementation)
    with open(instance+'/'+implementation+'/KeccakF-1600-opt64-settings.h', 'w') as f:
        f.write('#define Unrolling {0}\n'.format(unrolling))
        if (laneComplementing):
            f.write('#define UseBebigokimisa\n')
    copySourceFiles(instance, implementation,
                    [ 'brg_endian.h',
                      'KeccakSponge.c',
                      'KeccakSponge.h',
                      'KeccakF-1600-interface.h',
                      'KeccakF-1600-unrolling.macros',
                      'KeccakF-1600-64.macros',
                      'KeccakF-1600-opt64.c' ])
    copyVariantFiles(instance, implementation)
    writeImplementors(instance, implementation, Designers)

def makeSSE(instance, unrolling):
    implementation = 'sse'
    implementation = implementation + 'u{0}'.format(unrolling)
    print('  Implementation', implementation)
    makeDir(instance, implementation)
    with open(instance+'/'+implementation+'/KeccakF-1600-opt64-settings.h', 'w') as f:
        f.write('#define Unrolling {0}\n'.format(unrolling))
        f.write('#define UseSSE\n')
    copySourceFiles(instance, implementation,
                    [ 'brg_endian.h',
                      'KeccakSponge.c',
                      'KeccakSponge.h',
                      'KeccakF-1600-interface.h',
                      'KeccakF-1600-unrolling.macros',
                      'KeccakF-1600-simd128.macros',
                      'KeccakF-1600-opt64.c' ])
    copyVariantFiles(instance, implementation)
    with open(instance+'/'+implementation+'/architectures', 'w') as f:
        f.write('amd64\n')
        f.write('x86\n')
    writeImplementors(instance, implementation, Designers)

def makeMMX(instance, unrolling):
    implementation = 'mmx'
    implementation = implementation + 'u{0}'.format(unrolling)
    print('  Implementation', implementation)
    makeDir(instance, implementation)
    with open(instance+'/'+implementation+'/KeccakF-1600-opt64-settings.h', 'w') as f:
        f.write('#define Unrolling {0}\n'.format(unrolling))
        f.write('#define UseMMX\n')
    copySourceFiles(instance, implementation,
                    [ 'brg_endian.h',
                      'KeccakSponge.c',
                      'KeccakSponge.h',
                      'KeccakF-1600-interface.h',
                      'KeccakF-1600-unrolling.macros',
                      'KeccakF-1600-simd64.macros',
                      'KeccakF-1600-opt64.c' ])
    copyVariantFiles(instance, implementation)
    with open(instance+'/'+implementation+'/architectures', 'w') as f:
        f.write('amd64\n')
        f.write('x86\n')
    writeImplementors(instance, implementation, Designers)

def makeOpt32(instance, bitInterleavingTable, laneComplementing, schedule, unrolling):
    implementation = 'opt32bi'
    if (bitInterleavingTable):
        implementation = implementation + 'T'
    if (schedule == 3):
        implementation = implementation + '-rvk'
    else:
        implementation = implementation + '-s{0}'.format(schedule)
    if (laneComplementing):
        implementation = implementation + 'lc'
    implementation = implementation + 'u{0}'.format(unrolling)
    print('  Implementation', implementation)
    makeDir(instance, implementation)
    with open(instance+'/'+implementation+'/KeccakF-1600-opt32-settings.h', 'w') as f:
        f.write('#define Unrolling {0}\n'.format(unrolling))
        if (bitInterleavingTable):
            f.write('#define UseInterleaveTables\n')
        if (laneComplementing):
            f.write('#define UseBebigokimisa\n')
        f.write('#define UseSchedule {0}\n'.format(schedule))
    copySourceFiles(instance, implementation,
                    [ 'brg_endian.h',
                      'KeccakSponge.c',
                      'KeccakSponge.h',
                      'KeccakF-1600-interface.h',
                      'KeccakF-1600-unrolling.macros',
                      'KeccakF-1600-32.macros',
                      'KeccakF-1600-opt32.c' ])
    if (schedule == 3):
        copySourceFiles(instance, implementation, ['KeccakF-1600-32-rvk.macros'])
    else:
        copySourceFiles(instance, implementation, ['KeccakF-1600-32-s{0}.macros'.format(schedule)])
    copyVariantFiles(instance, implementation)
    if (schedule == 3):
        writeImplementors(instance, implementation, Designers + Ronny)
    else:
        writeImplementors(instance, implementation, Designers)

def makeARMasm(instance):
    implementation = 'armasm'
    print('  Implementation', implementation)
    makeDir(instance, implementation)
    copySourceFiles(instance, implementation,
                    [ 'KeccakSponge.c',
                      'KeccakSponge.h',
                      'KeccakF-1600-interface.h',
                      'KeccakF-1600-armgcc.s',
                      'KeccakF-1600-arm.c' ])
    copyVariantFiles(instance, implementation)
    with open(instance+'/'+implementation+'/architectures', 'w') as f:
        f.write('arm\n')
        f.write('armeabi\n')
    writeImplementors(instance, implementation, Ronny)

def makeSimple(instance):
    implementation = 'simple'
    print('  Implementation', implementation)
    makeDir(instance, implementation)
    copySourceFiles(instance, implementation,
                    [ 'Keccak-simple.c' ])
    copyVariantFilesNoWrapper(instance, implementation)
    shutil.copyfile('simple-'+instance+'.h', instance+'/'+implementation+'/Keccak-simple-settings.h')
    writeImplementors(instance, implementation, Ronny)

def makeSimple32BI(instance):
    implementation = 'simple32bi'
    print('  Implementation', implementation)
    makeDir(instance, implementation)
    copySourceFiles(instance, implementation,
                    [ 'Keccak-simple32BI.c' ])
    copyVariantFilesNoWrapper(instance, implementation)
    shutil.copyfile('simple-'+instance+'.h', instance+'/'+implementation+'/Keccak-simple-settings.h')
    writeImplementors(instance, implementation, Designers + Ronny)

def makeCompact(instance):
    implementation = 'compact'
    print('  Implementation', implementation)
    makeDir(instance, implementation)
    copySourceFiles(instance, implementation,
                    [ 'Keccak-compact.c',
                      'Keccak-compact.h' ])
    copyVariantFilesNoWrapper(instance, implementation)
    shutil.copyfile('simple-'+instance+'.h', instance+'/'+implementation+'/Keccak-compact-settings.h')
    writeImplementors(instance, implementation, Ronny)

def makeCompact8(instance):
    implementation = 'compact8'
    print('  Implementation', implementation)
    makeDir(instance, implementation)
    copySourceFiles(instance, implementation,
                    [ 'Keccak-compact8.c',
                      'Keccak-compact8.h' ])
    copyVariantFilesNoWrapper(instance, implementation)
    shutil.copyfile('simple-'+instance+'.h', instance+'/'+implementation+'/Keccak-compact8-settings.h')
    writeImplementors(instance, implementation, Designers + Ronny)

def makeAVR8(instance):
    implementation = 'avr8'
    print('  Implementation', implementation)
    makeDir(instance, implementation)
    copySourceFiles(instance, implementation,
                    [ 'AVR8-rotate64.h',
                      'AVR8-rotate64.s',
                      'Keccak-avr8.c',
                      'Keccak-avr8.h',
                      'Keccak-avr8-util.h',
                      'Keccak-avr8-util.s',
                      'KeccakF-1600-avr8.c' ])
    copyVariantFilesNoWrapper(instance, implementation)
    shutil.copyfile('simple-'+instance+'.h', instance+'/'+implementation+'/Keccak-avr8-settings.h')
    writeImplementors(instance, implementation, Ronny)

def makeAVR8asm(instance):
    implementation = 'avr8asm'
    print('  Implementation', implementation)
    makeDir(instance, implementation)
    copySourceFiles(instance, implementation,
                    [ 'Keccak-avr8.c',
                      'Keccak-avr8.h',
                      'Keccak-avr8-util.h',
                      'Keccak-avr8-util.s',
                      'KeccakF-1600-avr8asm.s' ])
    copyVariantFilesNoWrapper(instance, implementation)
    shutil.copyfile('simple-'+instance+'.h', instance+'/'+implementation+'/Keccak-avr8-settings.h')
    writeImplementors(instance, implementation, Ronny)

def eBASH_Keccak(r, c):
    instance = 'keccak'
    if (r+c != 1600):
        instance = instance + 'r{0}'.format(r) + 'c{0}'.format(c)
    elif (c != 576):
        instance = instance + 'c{0}'.format(c)
    print('Instance', instance)
    makeOpt64(instance, True, 24)
    makeOpt64(instance, True, 6)
    makeOpt64(instance, False, 6)
    makeOpt32(instance, False, True, 2, 4)
    makeOpt32(instance, True, True, 2, 4)
    #makeOpt32(instance, False, False, 2, 4)
    makeOpt32(instance, False, False, 3, 2)
    #makeOpt32(instance, False, True, 1, 4)
    makeSSE(instance, 2)
    makeMMX(instance, 1)
    makeARMasm(instance)
    makeSimple(instance)
    makeSimple32BI(instance)
    makeCompact(instance)
    makeCompact8(instance)
    makeAVR8(instance)
    makeAVR8asm(instance)
    shutil.copyfile('checksum-'+instance, instance+'/checksum')

eBASH_Keccak(r=576, c=1024)
eBASH_Keccak(r=832, c=768)
eBASH_Keccak(r=1024, c=576)
eBASH_Keccak(r=1088, c=512)
eBASH_Keccak(r=1152, c=448)
eBASH_Keccak(r=1344, c=256)
