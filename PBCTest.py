import os

late = [
]

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
    'CH_KEF_MH_SDH_DL_AM_2004',
    'CH_KEF_NoMH_AM_2004',
    'CHET_RSA_CDK_2017',
    'CR_CH_DSS_2020',
    'FCR_CH_PreQA_DKS_2020',
    'MCH_CDK_2017',

    'IB_CH_KEF_CZS_2014',
    'IB_CH_MD_LSX_2022',
    'IB_CH_ZSS_S1_2003',
    'IB_CH_ZSS_S2_2003',
    'ID_B_CollRes_XSL_2021',

    'DPCH_MXN_2022',
    'MAPCH_ZLW_2021',
    'PCH_DSS_2019',
    'PCHBA_TLL_2020',
    'RPCH_TMM_2022',
    'RPCH_XNM_2021'
    
] + late

# os.system(f'mvn -Dtest=PBCTest.BasicTimeTest test')

for scheme_type in ['CH', 'IBCH', 'PBCH']:
    os.makedirs(f'./data/PBC/{scheme_type}', exist_ok=True)
    for dirpath, dirnames, filenames in os.walk(f'./src/test/java/PBCTest/{scheme_type}Test'):
        for filename in filenames: 
            if filename[:-5] in done: continue
            # print(filename[:-5])
            open(f'./data/PBC/{scheme_type}/{filename[:-5]}.txt', 'w')
            os.system(f'mvn -Dtest=PBCTest.{scheme_type}Test.{filename[:-5]} test')

