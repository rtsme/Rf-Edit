"""
RF Online .dat editor -- a GUI front end for rf_dat.

Open a .dat, pick a record, edit its fields, save it back in the same binary
format. The point of doing it this way rather than in a hex editor is that the
schema is enforced on the way in and on the way out: a string can't overflow
its slot, a number can't overflow its type, and the header's field count and
record size are rewritten from the schema that was verified when the file was
opened.

Safety rules this enforces, because these are live server files:

  * On open, the file is parsed and re-encoded and the result compared to the
    original bytes. If they don't match, the schema is wrong for that file and
    saving is disabled -- editing it would corrupt fields you never touched.
  * On save, the original is copied to a timestamped .bak alongside it first.
  * Every field is validated as you leave the record, not silently truncated.

    python rf_editor.py [File.dat]
"""
import os
import shutil
import sys
import time
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from rf_dat import (SchemaError, Table, field_size, parse_value,
                    _STRING_RE)

# Where the Open dialog starts. Machine-specific, so it's only a convenience
# default -- set RF_SCRIPT_DIR to move it, and if neither exists the dialog
# just opens in the current folder rather than failing.
SCRIPT_DIR = os.environ.get(
    "RF_SCRIPT_DIR",
    r"C:\client and server\1_Server AOP\Zoneserver\RF_Bin\script")
PAGE_SIZE = 500

# Above this many cells the all-rows-in-memory approach gets slow and heavy
# enough to be worth a warning first (CombineTable.dat is ~10M).
BIG_FILE_CELLS = 2000000

# Cap on precomputed filter haystacks; past this only the leading text fields
# of each record are searchable, to keep typing in the filter box responsive.
SEARCH_CELL_BUDGET = 2000000


class Editor(tk.Tk):
    def __init__(self):
        tk.Tk.__init__(self)
        self.title("RF .dat editor")
        self.geometry("1150x720")

        self.table = None
        self.path = None
        self.safe_to_save = False
        self.modified = set()        # indices of records changed this session
        self.visible = []            # record indices matching the filter
        self.page = 0
        self.current = None          # index of the record in the form
        self.widgets = {}            # field name -> Entry
        self.label_fields = []
        self.search_fields = []
        self.search_keys = []
        self.backed_up = set()       # paths already backed up this session
        self._suspend_filter = False

        self._build_menu()
        self._build_layout()
        self._set_status("Open a .dat file to begin.")

    # ---------------------------------------------------------------- layout

    def _build_menu(self):
        bar = tk.Menu(self)
        filemenu = tk.Menu(bar, tearoff=0)
        filemenu.add_command(label="Open...", accelerator="Ctrl+O",
                             command=self.do_open)
        filemenu.add_command(label="Save", accelerator="Ctrl+S",
                             command=self.do_save)
        filemenu.add_command(label="Save As...", command=self.do_save_as)
        filemenu.add_separator()
        filemenu.add_command(label="Export CSV...", command=self.do_export_csv)
        filemenu.add_command(label="Import CSV...", command=self.do_import_csv)
        filemenu.add_separator()
        filemenu.add_command(label="Exit", command=self.do_quit)
        bar.add_cascade(label="File", menu=filemenu)
        self.config(menu=bar)
        self.bind_all("<Control-o>", lambda e: self.do_open())
        self.bind_all("<Control-s>", lambda e: self.do_save())
        self.protocol("WM_DELETE_WINDOW", self.do_quit)

    def _build_layout(self):
        head = ttk.Frame(self, padding=(8, 6))
        head.pack(fill="x")
        self.file_label = ttk.Label(head, text="No file open",
                                    font=("Segoe UI", 10, "bold"))
        self.file_label.pack(side="left")
        self.schema_label = ttk.Label(head, text="", foreground="#555")
        self.schema_label.pack(side="left", padx=12)

        panes = ttk.PanedWindow(self, orient="horizontal")
        panes.pack(fill="both", expand=True, padx=8)

        # ---- left: record list
        left = ttk.Frame(panes)
        panes.add(left, weight=1)

        filt = ttk.Frame(left)
        filt.pack(fill="x", pady=(0, 4))
        ttk.Label(filt, text="Filter:").pack(side="left")
        self.filter_var = tk.StringVar()
        self.filter_var.trace_add("write", lambda *a: self.apply_filter())
        ttk.Entry(filt, textvariable=self.filter_var).pack(
            side="left", fill="x", expand=True, padx=4)

        self.tree = ttk.Treeview(left, columns=("a", "b", "c"),
                                 show="headings", selectmode="browse")
        for col, width in (("a", 60), ("b", 110), ("c", 150)):
            self.tree.column(col, width=width, anchor="w")
        vs = ttk.Scrollbar(left, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=vs.set)
        self.tree.pack(side="left", fill="both", expand=True)
        vs.pack(side="right", fill="y")
        self.tree.bind("<<TreeviewSelect>>", self.on_select)
        self.tree.tag_configure("dirty", foreground="#b34700")

        nav = ttk.Frame(left)
        nav.pack(side="bottom", fill="x", pady=4)
        ttk.Button(nav, text="<", width=3,
                   command=lambda: self.turn_page(-1)).pack(side="left")
        self.page_label = ttk.Label(nav, text="")
        self.page_label.pack(side="left", padx=6)
        ttk.Button(nav, text=">", width=3,
                   command=lambda: self.turn_page(1)).pack(side="left")

        # ---- right: field form
        right = ttk.Frame(panes)
        panes.add(right, weight=3)
        self.record_label = ttk.Label(right, text="",
                                      font=("Segoe UI", 10, "bold"))
        self.record_label.pack(anchor="w", pady=(0, 4))

        self.canvas = tk.Canvas(right, highlightthickness=0)
        fs = ttk.Scrollbar(right, orient="vertical", command=self.canvas.yview)
        self.canvas.configure(yscrollcommand=fs.set)
        self.canvas.pack(side="left", fill="both", expand=True)
        fs.pack(side="right", fill="y")
        self.form = ttk.Frame(self.canvas)
        self.form_id = self.canvas.create_window((0, 0), window=self.form,
                                                 anchor="nw")
        self.form.bind("<Configure>", lambda e: self.canvas.configure(
            scrollregion=self.canvas.bbox("all")))
        self.canvas.bind("<Configure>", lambda e: self.canvas.itemconfigure(
            self.form_id, width=e.width))
        self.canvas.bind("<Enter>", lambda e: self.canvas.bind_all(
            "<MouseWheel>", self._on_wheel))
        self.canvas.bind("<Leave>", lambda e: self.canvas.unbind_all(
            "<MouseWheel>"))

        self.status = ttk.Label(self, relief="sunken", anchor="w",
                                padding=(6, 3))
        self.status.pack(fill="x", side="bottom")

    def _on_wheel(self, event):
        self.canvas.yview_scroll(-1 * (event.delta // 120), "units")

    def _set_status(self, text):
        self.status.config(text=text)

    # ------------------------------------------------------------------ open

    def do_open(self):
        path = filedialog.askopenfilename(
            title="Open .dat",
            initialdir=SCRIPT_DIR if os.path.isdir(SCRIPT_DIR) else ".",
            filetypes=[("RF data files", "*.dat"), ("All files", "*.*")])
        if path:
            self.load(path)

    def load(self, path):
        if not self.confirm_discard():
            return
        try:
            count, nfields, _rsize = Table.header_of(path)
        except (SchemaError, OSError) as e:
            messagebox.showerror("Can't open", str(e))
            return
        if count * nfields > BIG_FILE_CELLS:
            if not messagebox.askokcancel(
                    "Large file",
                    "%s holds %d records x %d fields.\n\nThis editor loads the "
                    "whole file into memory, so opening it may take a while "
                    "and use a lot of RAM.\n\nOpen anyway?"
                    % (os.path.basename(path), count, nfields)):
                return

        self._set_status("Loading %s..." % os.path.basename(path))
        self.update_idletasks()
        try:
            table = Table.open(path)
        except (SchemaError, OSError, ValueError) as e:
            messagebox.showerror("Can't open", str(e))
            self._set_status("Open failed.")
            return

        self.table = table
        self.path = path
        self.modified = set()
        self.current = None
        self.page = 0
        # Order matters: clearing the filter box fires apply_filter, and until
        # the label/search fields are rebuilt those still name columns from the
        # file that was open before, which don't exist in this one.
        self._pick_label_fields()
        self._build_search_keys()
        self._suspend_filter = True
        self.filter_var.set("")
        self._suspend_filter = False

        # The load-bearing check: if re-encoding what we just parsed doesn't
        # reproduce the file, the schema is wrong for this build and writing it
        # back would rewrite bytes we never meant to touch.
        self.safe_to_save = table.roundtrip_ok()

        self.file_label.config(text=os.path.basename(path))
        self.schema_label.config(
            text="%d records | %d fields | %d bytes/record | schema: %s"
                 % (len(table.rows), table.field_count, table.rec_size,
                    table.schema_source))
        self.apply_filter()

        if self.safe_to_save:
            self._set_status("Loaded. Round-trip verified -- safe to edit.")
        else:
            self.schema_label.config(foreground="#b00")
            messagebox.showwarning(
                "Schema mismatch -- read only",
                "This file parsed, but re-encoding it does not reproduce the "
                "original bytes, which means the schema doesn't truly match "
                "this build.\n\nSaving is disabled. You can look, but editing "
                "would corrupt fields you never touched.")
            self._set_status("Loaded READ-ONLY: schema does not round-trip.")

    def _pick_label_fields(self):
        """Choose two short-ish text columns to identify records in the list.

        The first string field is the item/class code, which is what you look
        records up by. For the second, prefer a field with "name" in it -- most
        schemas put readable English names in EngName or Name1, and the field
        that merely happens to come second (Ch_Class1 in Class.dat) says
        nothing useful about which record you're looking at.
        """
        strings = self._short_string_fields()
        self.label_fields = strings[:1]
        rest = strings[1:]
        # EngName before KorName: both match "name", but only one of them is
        # readable here -- KorName is Korean bytes in a non-UTF8 encoding.
        pick = ([n for n in rest if "engname" in n.lower()]
                or [n for n in rest if "name" in n.lower()
                    and "kor" not in n.lower()]
                or [n for n in rest if "name" in n.lower()]
                or rest)
        if pick:
            self.label_fields.append(pick[0])
        head = ["#"] + self.label_fields
        for col, text in zip(("a", "b", "c"), head + ["", ""]):
            self.tree.heading(col, text=text)

    def _short_string_fields(self):
        out = []
        for name, ftype in self.table.schema:
            m = _STRING_RE.match(ftype)
            if m and int(m.group(1)) <= 64:
                out.append(name)
        return out

    def _build_search_keys(self):
        """Precompute one lowercased haystack per record, for fast filtering.

        Filtering only the two list columns misses the obvious searches -- in
        Class.dat the class names live in EngName, twelve string fields in, so
        typing "mage" would find nothing. Searching every text field per
        keystroke is the other extreme: CombineTable.dat is 60375 records by
        ~140 string fields. So the haystacks are built once at load, and only
        capped to the leading fields on files big enough for it to matter.
        """
        fields = self._short_string_fields()
        if len(self.table.rows) * max(1, len(fields)) > SEARCH_CELL_BUDGET:
            fields = fields[:6]
        self.search_keys = [
            " ".join(str(row[f]) for f in fields).lower()
            for row in self.table.rows]
        self.search_fields = fields

    # ---------------------------------------------------------- list + paging

    def apply_filter(self):
        if not self.table or self._suspend_filter:
            return
        needle = self.filter_var.get().strip().lower()
        if needle:
            self.visible = [i for i, key in enumerate(self.search_keys)
                            if needle in key or needle == str(i)]
        else:
            self.visible = list(range(len(self.table.rows)))
        self.page = 0
        self.refresh_list()

    def page_count(self):
        return max(1, (len(self.visible) + PAGE_SIZE - 1) // PAGE_SIZE)

    def turn_page(self, delta):
        new = self.page + delta
        if 0 <= new < self.page_count():
            self.page = new
            self.refresh_list()

    def refresh_list(self):
        self.tree.delete(*self.tree.get_children())
        start = self.page * PAGE_SIZE
        for i in self.visible[start:start + PAGE_SIZE]:
            row = self.table.rows[i]
            vals = [str(i)] + [str(row[f])[:40] for f in self.label_fields]
            while len(vals) < 3:
                vals.append("")
            self.tree.insert("", "end", iid=str(i), values=vals,
                             tags=("dirty",) if i in self.modified else ())
        self.page_label.config(
            text="page %d/%d  (%d records)"
                 % (self.page + 1, self.page_count(), len(self.visible)))

    # ------------------------------------------------------------------ form

    def on_select(self, _event=None):
        sel = self.tree.selection()
        if not sel:
            return
        idx = int(sel[0])
        if idx == self.current:
            return
        if self.current is not None and not self.commit_form():
            # Validation failed -- put the selection back so the bad value
            # stays on screen where it can be fixed.
            self.tree.selection_set(str(self.current))
            return
        self.current = idx
        self.build_form(idx)

    def build_form(self, idx):
        for child in self.form.winfo_children():
            child.destroy()
        self.widgets = {}
        row = self.table.rows[idx]
        label = " / ".join(str(row[f]) for f in self.label_fields)
        self.record_label.config(text="Record %d   %s" % (idx, label))

        self.form.columnconfigure(2, weight=1)
        for r, (name, ftype) in enumerate(self.table.schema):
            ttk.Label(self.form, text=name).grid(
                row=r, column=0, sticky="w", padx=(2, 8), pady=1)
            ttk.Label(self.form, text=ftype, foreground="#888").grid(
                row=r, column=1, sticky="w", padx=(0, 8))
            var = tk.StringVar(value=str(row[name]))
            entry = ttk.Entry(self.form, textvariable=var)
            entry.grid(row=r, column=2, sticky="ew", padx=(0, 12), pady=1)
            if not self.safe_to_save:
                entry.state(["readonly"])
            self.widgets[name] = var
        self.canvas.yview_moveto(0)

    def commit_form(self):
        """Push the on-screen values into the record. False if anything is invalid."""
        if self.current is None or not self.widgets or not self.safe_to_save:
            return True
        row = self.table.rows[self.current]
        staged = {}
        for name, ftype in self.table.schema:
            text = self.widgets[name].get()
            if text == str(row[name]):
                continue
            try:
                staged[name] = parse_value(text, ftype)
            except ValueError as e:
                messagebox.showerror(
                    "Invalid value",
                    "Record %d, field %s (%s):\n\n%s"
                    % (self.current, name, ftype, e))
                return False
        if staged:
            row.update(staged)
            self.modified.add(self.current)
            self.search_keys[self.current] = " ".join(
                str(row[f]) for f in self.search_fields).lower()
            self.tree.item(str(self.current), tags=("dirty",),
                           values=[str(self.current)]
                                  + [str(row[f])[:40] for f in self.label_fields])
            self._set_status("Record %d: changed %s (unsaved)"
                             % (self.current, ", ".join(sorted(staged))))
        return True

    # ------------------------------------------------------------------ save

    def do_save(self):
        if not self.table:
            return
        if not self.safe_to_save:
            messagebox.showerror(
                "Read only",
                "Saving is disabled for this file: its schema doesn't "
                "round-trip, so writing it would corrupt untouched fields.")
            return
        if not self.commit_form():
            return
        self._write(self.path, backup=True)

    def do_save_as(self):
        if not self.table or not self.safe_to_save:
            return
        if not self.commit_form():
            return
        path = filedialog.asksaveasfilename(
            title="Save .dat as", defaultextension=".dat",
            initialfile=os.path.basename(self.path or "out.dat"),
            filetypes=[("RF data files", "*.dat"), ("All files", "*.*")])
        if path:
            self._write(path, backup=os.path.exists(path))
            self.path = path
            self.file_label.config(text=os.path.basename(path))

    def _write(self, path, backup):
        try:
            blob = self.table.to_bytes()
        except (ValueError, SchemaError) as e:
            messagebox.showerror("Save failed", str(e))
            return
        note = ""
        if backup and os.path.exists(path) and path not in self.backed_up:
            bak = "%s.%s.bak" % (path, time.strftime("%Y%m%d-%H%M%S"))
            try:
                shutil.copy2(path, bak)
                self.backed_up.add(path)
                note = "  (backup: %s)" % os.path.basename(bak)
            except OSError as e:
                if not messagebox.askokcancel(
                        "Backup failed",
                        "Couldn't write a backup:\n%s\n\nSave anyway?" % e):
                    return
        try:
            with open(path, "wb") as f:
                f.write(blob)
        except OSError as e:
            messagebox.showerror("Save failed", str(e))
            return
        n = len(self.modified)
        self.modified = set()
        self.refresh_list()
        self._set_status("Saved %s -- %d record(s) changed.%s"
                         % (os.path.basename(path), n, note))

    # ------------------------------------------------------------------- csv

    def do_export_csv(self):
        if not self.table:
            return
        self.commit_form()
        path = filedialog.asksaveasfilename(
            title="Export CSV", defaultextension=".csv",
            initialfile=os.path.splitext(os.path.basename(self.path))[0] + ".csv",
            filetypes=[("CSV", "*.csv"), ("All files", "*.*")])
        if not path:
            return
        self.table.export_csv(path)
        self._set_status("Exported %d records to %s"
                         % (len(self.table.rows), os.path.basename(path)))

    def do_import_csv(self):
        if not self.table or not self.safe_to_save:
            return
        path = filedialog.askopenfilename(
            title="Import CSV",
            filetypes=[("CSV", "*.csv"), ("All files", "*.*")])
        if not path:
            return
        try:
            rows = self.table.import_csv(path)
        except (ValueError, KeyError, OSError) as e:
            messagebox.showerror("Import failed",
                                 "%s\n\nThe file was not changed." % e)
            return
        self.modified = set(range(len(rows)))
        self.current = None
        self._build_search_keys()
        self.apply_filter()
        self._set_status("Imported %d records from %s -- not saved yet."
                         % (len(rows), os.path.basename(path)))

    # ------------------------------------------------------------------ misc

    def confirm_discard(self):
        if self.current is not None:
            self.commit_form()
        if not self.modified:
            return True
        return messagebox.askokcancel(
            "Unsaved changes",
            "%d record(s) have unsaved changes. Discard them?"
            % len(self.modified))

    def do_quit(self):
        if self.confirm_discard():
            self.destroy()


def main(argv):
    app = Editor()
    if len(argv) > 1:
        app.after(50, lambda: app.load(argv[1]))
    app.mainloop()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
