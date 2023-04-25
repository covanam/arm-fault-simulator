import os
from pathlib import Path

Path("reports").mkdir(exist_ok=True)

elf_files = os.listdir("files")

for f in elf_files:
    report_name = f.split('.')[0] + ".rpt"
    os.system("./build/armory_example --armv7m files/{} > reports/{}".format(f, report_name))
