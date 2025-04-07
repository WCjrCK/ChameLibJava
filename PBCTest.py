import os

late = ["CH_KEF_NoMH_AM_2004"]

done = [
    'CH_AMV_2017',
    'CH_CDK_2017',
    'CH_ET_BC_CDK_2017',
    'CH_ET_KOG_CDK_2017',
    'CH_FS_ECC_CCT_2024',
    'CH_KEF_CZK_2004',
    'CH_KEF_DL_CZT_2011',
    'CH_KEF_DLP_LLA_2012',
    'CH_KEF_MH_RSA_F_AM_2004',
    'CH_KEF_MH_RSANN_F_AM_2004',
    'CH_KEF_MH_SDH_DL_AM_2004'
] + late

os.system(f'mvn -Dtest=PBCTest.BasicTimeTest test')

for scheme_type in ['CH', 'IBCH', 'PBCH']:
    os.makedirs(f'./data/PBC/{scheme_type}', exist_ok=True)
    for dirpath, dirnames, filenames in os.walk(f'./src/test/java/PBCTest/{scheme_type}Test'):
        for filename in filenames: 
            if filename[:-5] in done: continue
            # print(filename[:-5])
            open(f'./data/PBC/{scheme_type}/{filename[:-5]}.txt', 'w')
            os.system(f'mvn -Dtest=PBCTest.{scheme_type}Test.{filename[:-5]} test')

