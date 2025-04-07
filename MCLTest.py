import os

late = ["CH_KEF_NoMH_AM_2004"]

done = [
] + late

# os.system(f'mvn -Dtest=MCLTest.BasicTimeTest test')

for scheme_type in ['CH', 'IBCH', 'PBCH']:
    os.makedirs(f'./data/MCL/{scheme_type}', exist_ok=True)
    for dirpath, dirnames, filenames in os.walk(f'./src/test/java/MCLTest/{scheme_type}Test'):
        for filename in filenames: 
            if filename[:-5] in done: continue
            open(f'./data/MCL/{scheme_type}/{filename[:-5]}.txt', 'w')
            os.system(f'mvn -Dtest=MCLTest.{scheme_type}Test.{filename[:-5]} test')

