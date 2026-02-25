import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from tkinterdnd2 import DND_FILES, TkinterDnD

class EB0Constants:
    SLOT_OFFSETS = {
        "Last Save": 0x1400,
        "Slot 1":    0x1700,
        "Slot 2":    0x1A00,
        "Slot 3":    0x1D00,
    }

    CHARS = {
        "Ninten":     0x40,
        "Ana":        0x80,
        "Lloyd":      0xC0,
        "Teddy":      0x100,
        "Pippi":      0x140,
        "EVE":        0x180,
        "Flying Man": 0x1C0,
    }

    MONEY = 0x10
    BANK  = 0x12

    STATS = [
        ("Level",      0x10, 1),
        ("Experience", 0x11, 3),
        ("Current HP", 0x14, 2),
        ("Max HP",     0x03, 2),
        ("Current PP", 0x16, 2),
        ("Max PP",     0x05, 2),
        ("Offense",    0x07, 2),
        ("Defense",    0x09, 2),
        ("Fight",      0x0B, 1),
        ("Speed",      0x0C, 1),
        ("Wisdom",     0x0D, 1),
        ("Strength",   0x0E, 1),
        ("Force",      0x0F, 1),
    ]

    WEAPON  = 0x28
    COIN    = 0x29
    RING    = 0x2A
    PENDANT = 0x2B

    ITEMS_START = 0x20
    ITEMS_COUNT = 8

    MAGIC_START = 0x30
    MAGIC_COUNT = 8

    NAME_START = 0x38
    NAME_LEN   = 7

    SLOT_SIZE = 0x300

    CHAR_DICT = [
        " ","*","*","*","*","*","*","*","*","*","*","*","*","*","*","*","*","*","*","*","*","*","*","*","*","*","*","*","*","*","*","*",
        "*","*","*","*","*","*","*","*","*","*","*","*","*","*","*","*","*","*","*","*","*","*","*","*","*","*","*","*","*","*","*","*",
        "*","*","*","*","*","*","*","*","*","*","*","*","*","*","*","*","*","*","*","*","*","*","*","*","*","*","*","*","*","*","*","*",
        "*","*","*","*","*","*","*","*","*","*","*","*","*","*","*","*","*","*","*","*","*","*","*","*","*","*","*","*","*","*","*","*",
        "*","*","*","*","*","*","*","*","*","*","*","*","*","*","*","*","*","*","*","*","*","*","*","*","*","*","*","*","*","*","*","*",
        "*","!","?","..","$","'",'"',"\\",'(',")",":",";"," ,","-",".","/","*","0","1","2","3","4","5","6","7","8","9","$","α","β","γ","π",
        "Ω","A","B","C","D","E","F","G","H","I","J","K","L","M","N","O","P","Q","R","S","T","U","V","W","X","Y","Z","*","*","*","*","*",
        "*","a","b","c","d","e","f","g","h","i","j","k","l","m","n","o","p","q","r","s","t","u","v","w","x","y","z",
    ]

    _CHAR_MAP = None

    @classmethod
    def char_map(cls):
        if cls._CHAR_MAP is None:
            cls._CHAR_MAP = {
                ch: idx for idx, ch in enumerate(cls.CHAR_DICT)
                if ch != "*"
            }
        return cls._CHAR_MAP

    @classmethod
    def decode_string(cls, raw_bytes):
        return "".join(
            cls.CHAR_DICT[b] for b in raw_bytes
            if b != 0 and b < len(cls.CHAR_DICT) and cls.CHAR_DICT[b] != "*"
        )

    @classmethod
    def encode_string(cls, text, length):
        mapping = cls.char_map()
        buf = bytearray(length)
        for i, ch in enumerate(text[:length]):
            buf[i] = mapping.get(ch, 0)
        return buf

    ITEM_NAMES = {
        0x00: "(Empty)",   0x01: "Big Bag",       0x02: "Phone Card",    0x03: "Crumbs",
        0x0A: "Butter Knife", 0x0B: "Surv. Knife", 0x0C: "Sword",        0x0D: "Katana",
        0x0E: "Stun Gun",  0x0F: "Air Gun",       0x10: "Plastic Bat",   0x11: "Wooden Bat",
        0x12: "Alum. Bat", 0x13: "Hank's Bat",    0x14: "Frying Pan",    0x15: "Nonstick Pan",
        0x16: "Iron Skillet", 0x17: "Slingshot",  0x18: "Boomerang",     0x19: "Insecticide",
        0x1A: "Super Spray", 0x1B: "Flea Bag",    0x1C: "Words o' Love", 0x1D: "Swear Words",
        0x1E: "Stky Machine", 0x1F: "Flashdark",  0x20: "StoneOrigin*",  0x21: "Poison Needle*",
        0x22: "Fl. Thrower", 0x23: "Bomb",        0x24: "Super Bomb",    0x25: "Laser Beam",
        0x26: "Plasma Beam", 0x28: "Rope",        0x2D: "Peace Coin",    0x2E: "Protect Coin",
        0x2F: "Magic Coin",  0x04: "Repel Ring",  0x30: "Brass Ring",    0x31: "Silver Ring",
        0x32: "Gold Ring",   0x33: "H2O Pendant", 0x34: "Fire Pendant",  0x35: "Earth Pendant",
        0x36: "Sea Pendant", 0x3C: "Orange Juice",0x3D: "French Fries",  0x3E: "Magic Herb",
        0x3F: "Hamburger",   0x40: "Sports Drink",0x41: "LifeUp Cream",  0x42: "Asthma Spray",
        0x43: "Antidote",    0x44: "Mouth Wash",  0x45: "Berry Tofu",    0x47: "Bread",
        0x48: "Noble Seed",  0x49: "PSI Stone",   0x4B: "Magic Ribbon",  0x4C: "Magic Candy",
        0x4E: "Quick Capsule",0x4F: "Wisdom Cap.",0x50: "Phys. Cap.",     0x51: "Force Cap.",
        0x52: "Fight Cap.",  0x55: "Basement Key",0x56: "Zoo Key",        0x57: "Ghost Key",
        0x58: "GGF's Diary", 0x59: "Pass",        0x5A: "Ticket",        0x5F: "Canary Chick",
        0x61: "Bottle Rocket",0x62: "Hat",        0x63: "Dentures",      0x64: "Ticket Stub",
        0x65: "IC Chip*",    0x66: "Ocarina",     0x68: "Franklin Badge",0x69: "Friendship Ring*",
        0x6B: "Onyx Hook",   0x6C: "Last Weapon", 0x6D: "Ruler",         0x6E: "Cash Card",
        0x6F: "Red Weed",    0x70: "Bullhorn",    0x71: "Map*",          0x7F: "Debug*",
        0xA6: "Real Rocket*",0xA8: "Time Machine*",
    }

    ITEM_LIST = sorted(ITEM_NAMES.items())

    STATUS_FLAGS = {
        "Normal":    0x00, "Cold":  0x01, "Poison":   0x02, "Puzzled": 0x04,
        "Confused":  0x08, "Sleep": 0x10, "Paralysis":0x20, "Stone":   0x40,
        "Fainted":   0x80,
    }

    STAT_DISPLAY_NAMES = {
        "Fight":    "Fight / Guts",
        "Strength": "Strength / Vitality",
        "Force":    "Force / IQ",
    }

    STAT_MAXES = {
        "Level": 99, "Experience": 999999,
        "Max HP": 999, "Current HP": 999,
        "Max PP": 999, "Current PP": 999,
        "Offense": 255, "Defense": 255,
        "Fight": 255, "Speed": 255,
        "Wisdom": 255, "Strength": 255, "Force": 255,
    }


def recalculate_checksum(data, slot_offset):
    cs = sum(
        int.from_bytes(data[slot_offset+2+i*2 : slot_offset+2+i*2+2], "little")
        for i in range(327)
    ) % 0x10000
    cs = (-cs) % 0x10000
    data[slot_offset]     = cs & 0xFF
    data[slot_offset + 1] = (cs >> 8) & 0xFF


DARK_BG     = "#1a1a2e"
PANEL_BG    = "#16213e"
ACCENT      = "#e94560"
TEXT_BRIGHT = "#eaeaea"
TEXT_DIM    = "#7a7a9a"
ENTRY_BG    = "#0f3460"
BORDER      = "#2a2a4a"
GREEN       = "#4ecca3"
YELLOW      = "#f5a623"


def styled_entry(parent, width=12):
    return tk.Entry(
        parent, width=width,
        bg=ENTRY_BG, fg=TEXT_BRIGHT,
        insertbackground=TEXT_BRIGHT,
        relief="flat", bd=4,
        font=("Consolas", 10)
    )


def section_label(parent, text):
    return tk.Label(parent, text=text, bg=PANEL_BG, fg=ACCENT,
                    font=("Consolas", 10, "bold"))


class SaveEditorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("EarthBound Beginnings  ·  Save Editor")
        self.root.geometry("860x700")
        self.root.configure(bg=DARK_BG)
        self.root.resizable(True, True)

        self.file_data    = None
        self.file_path    = None
        self.current_char = "Ninten"
        self.current_slot = "Last Save"

        self.root.drop_target_register(DND_FILES)
        self.root.dnd_bind('<<Drop>>', self.handle_drop)
        self._build_ui()

    def _build_ui(self):
        self._build_toolbar()
        self._build_body()

    def _build_toolbar(self):
        bar = tk.Frame(self.root, bg="#0d0d1a", height=44)
        bar.pack(side="top", fill="x")
        bar.pack_propagate(False)

        tk.Label(bar, text="Mother - 25th Anniversary Edition Save Editor", bg="#0d0d1a",
                 fg=ACCENT, font=("Consolas", 13, "bold")).pack(side="left", padx=14, pady=8)

        for text, cmd, bg, fg in [
            ("▶  OPEN", self.load_file, ENTRY_BG, GREEN),
            ("💾  SAVE", self.save_file, ACCENT, "white"),
        ]:
            tk.Button(bar, text=text, command=cmd, bg=bg, fg=fg,
                      activebackground=bg, activeforeground=fg,
                      bd=0, padx=14, pady=4,
                      font=("Consolas", 10, "bold"), cursor="hand2"
                      ).pack(side="left", padx=6, pady=6)

        tk.Label(bar, text="SLOT", bg="#0d0d1a", fg=TEXT_DIM,
                 font=("Consolas", 9)).pack(side="left", padx=(18, 4))

        self.slot_var = tk.StringVar(value="Last Save")
        slot_cb = ttk.Combobox(bar, textvariable=self.slot_var,
                               values=list(EB0Constants.SLOT_OFFSETS.keys()),
                               width=11, state="readonly", font=("Consolas", 10))
        slot_cb.pack(side="left", pady=6)
        slot_cb.bind("<<ComboboxSelected>>", self.on_slot_select)

        self.status_lbl = tk.Label(bar, text="Drop a save file here",
                                   bg="#0d0d1a", fg=TEXT_DIM, font=("Consolas", 9))
        self.status_lbl.pack(side="right", padx=14)

    def _build_body(self):
        body = tk.Frame(self.root, bg=DARK_BG)
        body.pack(expand=True, fill="both", padx=10, pady=8)

        self._build_sidebar(body)

        right = tk.Frame(body, bg=DARK_BG)
        right.pack(side="right", expand=True, fill="both")

        self._build_global_panel(right)
        self._build_notebook(right)

    def _build_sidebar(self, parent):
        sidebar = tk.Frame(parent, bg=PANEL_BG, width=130)
        sidebar.pack(side="left", fill="y", padx=(0, 8))
        sidebar.pack_propagate(False)

        tk.Label(sidebar, text="PARTY", bg=PANEL_BG, fg=ACCENT,
                 font=("Consolas", 10, "bold")).pack(pady=(10, 4))

        self.char_listbox = tk.Listbox(
            sidebar, font=("Consolas", 10),
            bg=PANEL_BG, fg=TEXT_BRIGHT,
            selectbackground=ACCENT, selectforeground="white",
            bd=0, highlightthickness=0, activestyle="none"
        )
        for ch in EB0Constants.CHARS:
            self.char_listbox.insert(tk.END, f"  {ch}")
        self.char_listbox.pack(fill="both", expand=True, pady=4, padx=4)
        self.char_listbox.bind("<<ListboxSelect>>", self.on_char_select)
        self.char_listbox.selection_set(0)

    def _build_notebook(self, parent):
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("TNotebook", background=DARK_BG, borderwidth=0)
        style.configure("TNotebook.Tab", background=PANEL_BG, foreground=TEXT_DIM,
                        padding=[12, 4], font=("Consolas", 9, "bold"))
        style.map("TNotebook.Tab",
                  background=[("selected", ENTRY_BG)],
                  foreground=[("selected", GREEN)])

        nb = ttk.Notebook(parent)
        nb.pack(expand=True, fill="both", pady=(6, 0))

        self.tab_stats = tk.Frame(nb, bg=PANEL_BG)
        self.tab_equip = tk.Frame(nb, bg=PANEL_BG)
        self.tab_items = tk.Frame(nb, bg=PANEL_BG)
        self.tab_name  = tk.Frame(nb, bg=PANEL_BG)

        nb.add(self.tab_stats, text="  Stats  ")
        nb.add(self.tab_equip, text="  Equipment  ")
        nb.add(self.tab_items, text="  Items  ")
        nb.add(self.tab_name,  text="  Name  ")

        self._build_stats_tab()
        self._build_equip_tab()
        self._build_items_tab()
        self._build_name_tab()

    def _build_global_panel(self, parent):
        frame = tk.Frame(parent, bg=PANEL_BG, pady=8, padx=10)
        frame.pack(fill="x", pady=(0, 6))

        section_label(frame, "GLOBAL ECONOMY").grid(row=0, column=0, columnspan=4, sticky="w", pady=(0, 6))

        self.g_entries = {}
        for col, (label, key, off, sz) in enumerate([
            ("Cash ($)",   "Cash", EB0Constants.MONEY, 2),
            ("Bank ($$$)", "Bank", EB0Constants.BANK,  3),
        ]):
            tk.Label(frame, text=label, bg=PANEL_BG, fg=TEXT_DIM,
                     font=("Consolas", 9)).grid(row=1, column=col*2, sticky="e", padx=(8, 4))
            e = styled_entry(frame, width=10)
            e.grid(row=1, column=col*2+1, padx=(0, 20))
            self.g_entries[key] = (e, off, sz)

    def _build_stats_tab(self):
        tab = self.tab_stats
        self.s_entries = {}

        section_label(tab, "CHARACTER STATS").grid(row=0, column=0, columnspan=4,
                                                    sticky="w", padx=12, pady=(10, 6))
        for i, (name, off, sz) in enumerate(EB0Constants.STATS):
            r, c = divmod(i, 2)
            display = EB0Constants.STAT_DISPLAY_NAMES.get(name, name)
            tk.Label(tab, text=display, bg=PANEL_BG, fg=TEXT_DIM,
                     font=("Consolas", 9), width=20, anchor="e"
                     ).grid(row=r+1, column=c*2, sticky="e", padx=(12, 4), pady=3)
            e = styled_entry(tab)
            e.grid(row=r+1, column=c*2+1, sticky="w", padx=(0, 16), pady=3)
            self.s_entries[name] = (e, off, sz)

        tk.Label(tab, text="Status", bg=PANEL_BG, fg=TEXT_DIM,
                 font=("Consolas", 9), width=12, anchor="e"
                 ).grid(row=10, column=0, sticky="e", padx=(12, 4), pady=3)
        self.status_var = tk.StringVar(value="Normal")
        ttk.Combobox(tab, textvariable=self.status_var,
                     values=list(EB0Constants.STATUS_FLAGS.keys()),
                     width=12, state="readonly", font=("Consolas", 9)
                     ).grid(row=10, column=1, sticky="w", padx=(0, 16), pady=3)

        tk.Button(tab, text="MAX ALL STATS", command=self.max_stats,
                  bg=YELLOW, fg="#1a1a2e", bd=0, padx=10, pady=3,
                  font=("Consolas", 9, "bold"), cursor="hand2"
                  ).grid(row=11, column=0, columnspan=4, pady=(14, 4))

    def _build_equip_tab(self):
        tab = self.tab_equip
        self.e_combos = {}
        self._item_names = ["(Empty)"] + [n for i, n in EB0Constants.ITEM_LIST if i != 0]

        section_label(tab, "EQUIPPED ITEMS").grid(row=0, column=0, columnspan=2,
                                                   sticky="w", padx=12, pady=(10, 6))
        for row, (label, off) in enumerate([
            ("Weapon",  EB0Constants.WEAPON),
            ("Coin",    EB0Constants.COIN),
            ("Ring",    EB0Constants.RING),
            ("Pendant", EB0Constants.PENDANT),
        ]):
            tk.Label(tab, text=label, bg=PANEL_BG, fg=TEXT_DIM,
                     font=("Consolas", 9), width=10, anchor="e"
                     ).grid(row=row+1, column=0, sticky="e", padx=(12, 6), pady=5)
            var = tk.StringVar(value="(Empty)")
            ttk.Combobox(tab, textvariable=var, values=self._item_names,
                         width=20, state="readonly", font=("Consolas", 9)
                         ).grid(row=row+1, column=1, sticky="w", pady=5)
            self.e_combos[label] = (var, off)

    def _build_items_tab(self):
        tab = self.tab_items
        self.i_combos = []

        section_label(tab, "INVENTORY  (8 slots)").grid(row=0, column=0, columnspan=3,
                                                          sticky="w", padx=12, pady=(10, 6))
        item_names = ["(Empty)"] + [n for i, n in EB0Constants.ITEM_LIST if i != 0]
        for slot in range(EB0Constants.ITEMS_COUNT):
            tk.Label(tab, text=f"Slot {slot+1}", bg=PANEL_BG, fg=TEXT_DIM,
                     font=("Consolas", 9), width=7, anchor="e"
                     ).grid(row=slot+1, column=0, sticky="e", padx=(12, 6), pady=4)
            var = tk.StringVar(value="(Empty)")
            ttk.Combobox(tab, textvariable=var, values=item_names,
                         width=20, state="readonly", font=("Consolas", 9)
                         ).grid(row=slot+1, column=1, sticky="w", pady=4)
            self.i_combos.append(var)

        tk.Button(tab, text="CLEAR ALL SLOTS", command=self.clear_items,
                  bg=PANEL_BG, fg=ACCENT, bd=1, relief="solid", padx=10, pady=3,
                  font=("Consolas", 9), cursor="hand2"
                  ).grid(row=9, column=1, sticky="w", pady=(10, 0))

    def _build_name_tab(self):
        tab = self.tab_name
        section_label(tab, "CHARACTER NAME").pack(anchor="w", padx=12, pady=(10, 6))
        tk.Label(tab, text="(7 chars max  —  A-Z a-z 0-9 . - ! ?)",
                 bg=PANEL_BG, fg=TEXT_DIM, font=("Consolas", 8)).pack(anchor="w", padx=12)
        self.name_entry = styled_entry(tab, width=10)
        self.name_entry.pack(anchor="w", padx=14, pady=8)

    def slot_base(self):
        return EB0Constants.SLOT_OFFSETS[self.current_slot]

    def char_offset(self):
        return EB0Constants.CHARS[self.current_char]

    def handle_drop(self, event):
        self.process_file(event.data.strip('{}'))

    def load_file(self):
        path = filedialog.askopenfilename(
            filetypes=[("Save files", "*.sav *.SAV"), ("All", "*.*")]
        )
        if path:
            self.process_file(path)

    def process_file(self, path):
        try:
            with open(path, "rb") as f:
                self.file_data = bytearray(f.read())
            self.file_path = path
            filename = path.replace("\\", "/").split("/")[-1]
            self.status_lbl.config(text=f"✔  {filename}", fg=GREEN)
            self.refresh_ui()
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def on_slot_select(self, _event=None):
        if not self.file_data:
            return
        self.current_slot = self.slot_var.get()
        self.refresh_ui()

    def on_char_select(self, _event=None):
        if not self.file_data:
            return
        sel = self.char_listbox.curselection()
        if sel:
            self.current_char = list(EB0Constants.CHARS.keys())[sel[0]]
            self.refresh_ui()

    def _read_int(self, addr, size):
        return int.from_bytes(self.file_data[addr:addr+size], "little")

    def _write_int(self, addr, value, size):
        self.file_data[addr:addr+size] = value.to_bytes(size, "little")

    def refresh_ui(self):
        if not self.file_data:
            return
        base = self.slot_base()
        coff = self.char_offset()

        for _, (ent, off, sz) in self.g_entries.items():
            ent.delete(0, tk.END)
            ent.insert(0, str(self._read_int(base + off, sz)))

        for name, (ent, off, sz) in self.s_entries.items():
            ent.delete(0, tk.END)
            ent.insert(0, str(self._read_int(base + coff + off, sz)))

        status_byte = self.file_data[base + coff]
        self.status_var.set(
            next((n for n, f in EB0Constants.STATUS_FLAGS.items() if f == status_byte), "Normal")
        )

        for label, (var, off) in self.e_combos.items():
            byte_val = self.file_data[base + coff + off]
            name = EB0Constants.ITEM_NAMES.get(byte_val, "(Empty)")
            var.set(name if name in self._item_names else "(Empty)")

        for slot, var in enumerate(self.i_combos):
            byte_val = self.file_data[base + coff + EB0Constants.ITEMS_START + slot]
            name = EB0Constants.ITEM_NAMES.get(byte_val, "(Empty)")
            var.set(name if name in self._item_names else "(Empty)")

        raw = self.file_data[
            base + coff + EB0Constants.NAME_START:
            base + coff + EB0Constants.NAME_START + EB0Constants.NAME_LEN
        ]
        self.name_entry.delete(0, tk.END)
        self.name_entry.insert(0, EB0Constants.decode_string(raw))

    def _item_name_to_id(self, display_name):
        return next(
            (item_id for item_id, n in EB0Constants.ITEM_NAMES.items() if n == display_name),
            0x00
        )

    def _write_slot(self, base, coff, errors):
        for name, (ent, off, sz) in self.g_entries.items():
            try:
                self._write_int(base + off, int(ent.get()), sz)
            except Exception:
                if name not in errors:
                    errors.append(name)

        for name, (ent, off, sz) in self.s_entries.items():
            try:
                self._write_int(base + coff + off, int(ent.get()), sz)
            except Exception:
                if name not in errors:
                    errors.append(name)

        self.file_data[base + coff] = EB0Constants.STATUS_FLAGS.get(self.status_var.get(), 0x00)

        for label, (var, off) in self.e_combos.items():
            self.file_data[base + coff + off] = self._item_name_to_id(var.get())

        for slot, var in enumerate(self.i_combos):
            self.file_data[base + coff + EB0Constants.ITEMS_START + slot] = self._item_name_to_id(var.get())

        encoded = EB0Constants.encode_string(self.name_entry.get(), EB0Constants.NAME_LEN)
        self.file_data[
            base + coff + EB0Constants.NAME_START:
            base + coff + EB0Constants.NAME_START + EB0Constants.NAME_LEN
        ] = encoded

    def sync_data(self):
        if not self.file_data:
            return
        coff   = self.char_offset()
        errors = []

        self._write_slot(0x1400, coff, errors)
        self._write_slot(0x1700, coff, errors)
        recalculate_checksum(self.file_data, 0x1700)

        if errors:
            messagebox.showwarning(
                "Invalid values",
                f"Could not save: {', '.join(errors)}\nMake sure fields contain valid numbers."
            )

    def max_stats(self):
        for name, (ent, _, __) in self.s_entries.items():
            if name in EB0Constants.STAT_MAXES:
                ent.delete(0, tk.END)
                ent.insert(0, str(EB0Constants.STAT_MAXES[name]))

    def clear_items(self):
        for var in self.i_combos:
            var.set("(Empty)")

    def save_file(self):
        if not self.file_data:
            messagebox.showwarning("No file", "Open a save file first.")
            return
        if not messagebox.askyesno("Confirm Save",
                                   "⚠  Make sure you have a backup!\n\nWrite changes to disk?"):
            return
        self.sync_data()
        try:
            with open(self.file_path, "wb") as f:
                f.write(self.file_data)
            messagebox.showinfo("Saved", "✔  File updated successfully!")
        except Exception as e:
            messagebox.showerror("Error", str(e))


if __name__ == "__main__":
    root = TkinterDnD.Tk()
    app  = SaveEditorApp(root)
    root.mainloop()