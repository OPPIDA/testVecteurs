# Temporary utility to parse test vector imput file formats and convert them to JSON
# must be adapted for each file because the format is not universal (see vecteurs/README.md)
import json


vec = []

V = {}
V["operation"] = "SIGN"
V["expected"] = "OK"
V["curve"] = "s"

def reset():
    global V
    r = {}
    r["operation"] = V["operation"]
    r["expected"] = V["expected"]
    r["curve"] = V["curve"]
    V = r
    V["da"] = ""
    V["digest"] = ""
    V["r"] = ""
    V["s"] = ""
    V["k"] = ""

with open("../../../Desktop/SigGenComponent.txt", 'r') as f:
    for line in f:
        if line.startswith("[P-"):
            V["curve"] = line[1:].split(",")[0].replace("P-192", "secp192r1").replace("P-224", "secp224r1").replace("P-256", "secp256r1").replace("P-384", "secp384r1").replace("P-521", "secp521r1")
        if line.startswith("Msg = "):
            V["digest"] = line.split(" = ")[1].strip()
        if line.startswith("d = "):
            V["da"] = line.split(" = ")[1].strip()
        if line.startswith("k = "):
            V["k"] = line.split(" = ")[1].strip()
        if line.startswith("R = "):
            V["r"] = line.split(" = ")[1].strip()
        if line.startswith("S = "):
            V["s"] = line.split(" = ")[1].strip()
            if V["curve"] == "secp192r1" or V["curve"] == "secp224r1" or V["curve"] == "secp256r1":
                vec.append(V)
            reset()

f = {}
f["type"] = None
f["alg"] = "ECDSA"
f["mode"] = None
f["vectors"] = vec
json.dump(f, open("/tmp/json.json", "w"))