import os
from pathlib import Path

Path("reports").mkdir(exist_ok=True)
Path("reports/gcc_o2").mkdir(exist_ok=True)
Path("reports/gcc_o3").mkdir(exist_ok=True)
Path("reports/gcc_os").mkdir(exist_ok=True)
Path("reports/clang_o2").mkdir(exist_ok=True)
Path("reports/clang_o3").mkdir(exist_ok=True)
Path("reports/clang_os").mkdir(exist_ok=True)

for dir in os.listdir("files"):
    for f in os.listdir(os.path.join("files", dir)):
        report_name = os.path.join("reports", dir, f.split('.')[0] + ".rpt")
        print("Simulating ", f)
        os.system("./build/armory_example --armv7m {} > {}".format(os.path.join("files", dir, f), report_name))
