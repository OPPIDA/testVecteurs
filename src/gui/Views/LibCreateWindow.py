from ..guiUtils import *
import shutil
from ...utils import *
import json


class LibCreateWindow:

    def __init__(self):
        char_width = 7  # default font size
        window_width = 104 * char_width
        combo_width = 25
        txt_width = 12
        space_width = (window_width // char_width - txt_width * 2 - combo_width * 2) // 3
        two_cols = txt_width * 1 + space_width * 1 + combo_width * 2 + 1

        layout = [
            [psg.VPush()],
            [psg.Push(), psg.Text("Language :", size=txt_width),
             psg.Combo([], size=combo_width, key="-langselect-", readonly=True),
             psg.Push(), psg.Text("Name :", size=txt_width),
             psg.InputText("", size=combo_width, key="-name-"), psg.Push()],
            [psg.Push(), psg.Text("Description :", size=txt_width),
             psg.Multiline("", size=(two_cols, 10), no_scrollbar=True, autoscroll=True, key="-desc-"),
             psg.Push()],
            [psg.Push(), psg.Button("Back"), psg.Button("Create"), psg.Push()],
            [psg.VPush()],
        ]

        self.window = psg.Window(title="TestVecteur", layout=layout, size=(window_width, 250), finalize=True)
        # Only C supported right now
        langs = ["C"]
        self.window["-langselect-"].update(values=langs, value=langs[0])

    def handleEvents(self, event, value):
        if event == "Create":
            name = value["-name-"]
            desc = value["-desc-"]
            lang = value["-langselect-"]
            dst = f"bin/{name}"
            shutil.copytree(f"bin/Templates/{lang}", dst)
            # replace spaces with underscore because the Enums are separated by spaces (see src/utils.py)
            RunnerConfs[name.replace(" ", "_")] = {
                "type": lang,
                "libName": name,
                "binary_dir": dst,
                "description": desc
            }
            with open("src/runners.json", "w") as f:
                json.dump(RunnerConfs, f)
            # Modifications on the other module variables are only in the scope of this module
            # so the UI cannot be updated. At least I didn't find a way to do it properly
            psuccess("Library successfully created ! Reload the app for the changes to take effect.")
            psuccess(f"Edit the source code in {dst}")
