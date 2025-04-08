import os

done = [
    'CH_AMV_2017',
    'CH_ET_KOG_CDK_2017',
    'CH_FS_ECC_CCT_2024',
    'CH_KEF_CZK_2004',
    'CH_KEF_DL_CZT_2011',
    'CH_KEF_DLP_LLA_2012',
    'CH_KEF_MH_SDH_DL_AM_2004',
    'CR_CH_DSS_2020',
    'FCR_CH_PreQA_DKS_2020',

    'IB_CH_KEF_CZS_2014',
    'IB_CH_ZSS_S1_2003',
    '',
]

# os.system(f'mvn -Dtest=MCLTest.BasicTimeTest test')

for scheme_type in ['CH', 'IBCH', 'PBCH']:
    os.makedirs(f'./data/MCL/{scheme_type}', exist_ok=True)
    for dirpath, dirnames, filenames in os.walk(f'./src/test/java/MCLTest/{scheme_type}Test'):
        for filename in filenames: 
            if filename[:-5] in done: continue
            open(f'./data/MCL/{scheme_type}/{filename[:-5]}.txt', 'w')
            os.system(f'mvn -Dtest=MCLTest.{scheme_type}Test.{filename[:-5]} test')

