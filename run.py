import os
from pathlib import Path

Path("reports").mkdir(exist_ok=True)
Path("reports/gcc_o0").mkdir(exist_ok=True)
Path("reports/gcc_o1").mkdir(exist_ok=True)
Path("reports/gcc_o2").mkdir(exist_ok=True)
Path("reports/gcc_o3").mkdir(exist_ok=True)
Path("reports/gcc_os").mkdir(exist_ok=True)
Path("reports/clang_o0").mkdir(exist_ok=True)
Path("reports/clang_o1").mkdir(exist_ok=True)
Path("reports/clang_o2").mkdir(exist_ok=True)
Path("reports/clang_o3").mkdir(exist_ok=True)
Path("reports/clang_os").mkdir(exist_ok=True)

for dir in os.listdir("rasm_files"):
    for f in os.listdir(os.path.join("rasm_files", dir)):
        report_name = os.path.join("reports", dir, f.split('.')[0] + ".rpt")
        print("Simulating ", f)
        os.system("./build/armory_example --armv7m {} > {}".format(os.path.join("rasm_files", dir, f), report_name))
