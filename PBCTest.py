import os

for scheme_type in ['CH', 'IBCH', 'PBCH']:
    os.makedirs(f'./data/PBC/{scheme_type}', exist_ok=True)
    for dirpath, dirnames, filenames in os.walk(f'./src/test/java/PBCTest/{scheme_type}Test'):
        for filename in filenames:
            open(f'./data/PBC/{scheme_type}/{filename[:-5]}.txt', 'w')


os.system(f'mvn -Dtest=PBCTest.CHTest.CH_KEF_MH_RSA_F_AM_2004 test')

