"""
RF server data workbench.

The whole loop in one window:

    Open Server    point at a server root (e.g. C:\\client and server\\1_Server AOP)
    Create Repo    convert every .dat it finds into CSV, mirroring the server's
                   folder structure, and verify each one rebuilds byte-exactly
    ...            edit the CSVs in your IDE, commit, review
    Open Repo      re-open that repo later
    Preview        what your edits would change on the server, down to the field
    Build          write the changed tables back into the server's .dat files

Nothing writes to the server until you press Build and confirm, and Build backs
up every file it touches into the repo's backups/<timestamp>/ folder first.

    python rf_workbench.py
"""
import os
import queue
import sys
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

import rf_repo
from rf_dat import SchemaError
from rf_repo import Status


class Workbench(tk.Tk):
    def __init__(self):
        tk.Tk.__init__(self)
        self.title("RF server data workbench")
        self.geometry("1180x740")

        self.server = None
        self.repo = None
        self.statuses = []
        self.busy = False
        self.q = queue.Queue()

        self._build_ui()
        self._refresh_buttons()
        self._say("Start with Open Server, or Open Repo if you already have one.")

    # ------------------------------------------------------------------ ui

    def _build_ui(self):
        bar = ttk.Frame(self, padding=(8, 8))
        bar.pack(fill="x")
        self.btn_open_server = ttk.Button(bar, text="Open Server...",
                                          command=self.do_open_server)
        self.btn_create = ttk.Button(bar, text="Create Repo...",
                                     command=self.do_create_repo)
        self.btn_open_repo = ttk.Button(bar, text="Open Repo...",
                                        command=self.do_open_repo)
        self.btn_preview = ttk.Button(bar, text="Preview Changes",
                                      command=self.do_preview)
        self.btn_build = ttk.Button(bar, text="Build to Server...",
                                    command=self.do_build)
        for b in (self.btn_open_server, self.btn_create, self.btn_open_repo):
            b.pack(side="left", padx=(0, 6))
        ttk.Separator(bar, orient="vertical").pack(side="left", fill="y",
                                                   padx=10)
        self.btn_preview.pack(side="left", padx=(0, 6))
        self.btn_build.pack(side="left")

        paths = ttk.Frame(self, padding=(10, 0))
        paths.pack(fill="x")
        self.lbl_server = ttk.Label(paths, text="Server: -", foreground="#555")
        self.lbl_server.pack(anchor="w")
        self.lbl_repo = ttk.Label(paths, text="Repo:   -", foreground="#555")
        self.lbl_repo.pack(anchor="w")

        filt = ttk.Frame(self, padding=(10, 8))
        filt.pack(fill="x")
        ttk.Label(filt, text="Show:").pack(side="left")
        self.show_var = tk.StringVar(value="Changed and problems")
        box = ttk.Combobox(filt, textvariable=self.show_var, width=24,
                           state="readonly",
                           values=["Changed and problems", "Changed only",
                                   "Problems only", "Everything"])
        box.pack(side="left", padx=6)
        box.bind("<<ComboboxSelected>>", lambda e: self._fill_list())
        ttk.Label(filt, text="Filter:").pack(side="left", padx=(14, 0))
        self.filter_var = tk.StringVar()
        self.filter_var.trace_add("write", lambda *a: self._fill_list())
        ttk.Entry(filt, textvariable=self.filter_var, width=34).pack(
            side="left", padx=6)
        self.lbl_counts = ttk.Label(filt, text="", foreground="#555")
        self.lbl_counts.pack(side="left", padx=14)

        panes = ttk.PanedWindow(self, orient="horizontal")
        panes.pack(fill="both", expand=True, padx=10)

        left = ttk.Frame(panes)
        panes.add(left, weight=3)
        self.tree = ttk.Treeview(left, columns=("table", "state", "detail"),
                                 show="headings", selectmode="browse")
        for col, text, w in (("table", "Table", 420), ("state", "Status", 90),
                             ("detail", "Detail", 170)):
            self.tree.heading(col, text=text)
            self.tree.column(col, width=w, anchor="w")
        sv = ttk.Scrollbar(left, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=sv.set)
        self.tree.pack(side="left", fill="both", expand=True)
        sv.pack(side="right", fill="y")
        self.tree.bind("<<TreeviewSelect>>", self.on_select)
        self.tree.tag_configure("changed", foreground="#b34700")
        self.tree.tag_configure("error", foreground="#b00000")
        self.tree.tag_configure("missing", foreground="#777")

        right = ttk.Frame(panes)
        panes.add(right, weight=2)
        self.lbl_detail = ttk.Label(right, text="Select a table to see its "
                                                "field-level changes.",
                                    font=("Segoe UI", 9, "bold"))
        self.lbl_detail.pack(anchor="w", pady=(0, 4))
        self.diff = ttk.Treeview(right, columns=("rec", "field", "old", "new"),
                                 show="headings")
        for col, text, w in (("rec", "Record", 60), ("field", "Field", 130),
                             ("old", "On server", 130), ("new", "In repo", 130)):
            self.diff.heading(col, text=text)
            self.diff.column(col, width=w, anchor="w")
        dv = ttk.Scrollbar(right, orient="vertical", command=self.diff.yview)
        self.diff.configure(yscrollcommand=dv.set)
        self.diff.pack(side="left", fill="both", expand=True)
        dv.pack(side="right", fill="y")

        foot = ttk.Frame(self, padding=(10, 6))
        foot.pack(fill="x", side="bottom")
        self.progress = ttk.Progressbar(foot, mode="determinate", length=260)
        self.progress.pack(side="right")
        self.status = ttk.Label(foot, text="", anchor="w")
        self.status.pack(side="left", fill="x", expand=True)

    def _say(self, text):
        self.status.config(text=text)

    def _refresh_buttons(self):
        def state(on):
            return "normal" if on and not self.busy else "disabled"
        self.btn_open_server.config(state=state(True))
        self.btn_open_repo.config(state=state(True))
        self.btn_create.config(state=state(self.server is not None))
        self.btn_preview.config(state=state(self.repo is not None))
        self.btn_build.config(
            state=state(self.repo is not None
                        and any(s.state == Status.CHANGED
                                for s in self.statuses)))

    # ------------------------------------------------------- worker plumbing

    def _run(self, work, done):
        """Run work(progress) off the UI thread; call done(ok, result) after."""
        self.busy = True
        self._refresh_buttons()
        self.progress.config(value=0, maximum=100)

        def progress(i, total, msg):
            self.q.put(("progress", i, total, msg))

        def target():
            try:
                self.q.put(("done", True, work(progress)))
            except Exception as e:                      # surfaced in the UI
                self.q.put(("done", False, e))

        threading.Thread(target=target, daemon=True).start()
        self._poll(done)

    def _poll(self, done):
        try:
            while True:
                item = self.q.get_nowait()
                if item[0] == "progress":
                    _tag, i, total, msg = item
                    self.progress.config(maximum=max(total, 1), value=i)
                    self._say("%d/%d  %s" % (i, total, msg[-70:]))
                else:
                    _tag, ok, result = item
                    self.busy = False
                    self.progress.config(value=0)
                    self._refresh_buttons()
                    done(ok, result)
                    return
        except queue.Empty:
            pass
        self.after(60, lambda: self._poll(done))

    # ------------------------------------------------------------- commands

    def do_open_server(self):
        start = os.environ.get("RF_SERVER_DIR", "")
        path = filedialog.askdirectory(
            title="Select the server or client root",
            initialdir=start if start and os.path.isdir(start) else None)
        if not path:
            return
        n_dat = len(rf_repo.find_dats(path))
        n_edf = len(rf_repo.find_edfs(path))
        if not n_dat and not n_edf:
            messagebox.showwarning(
                "No RF data files",
                "Found no .dat or .edf files anywhere under\n%s\n\nIs that "
                "the server or client root?" % path)
            return
        self.server = path
        self.lbl_server.config(
            text="Source: %s   (%d .dat, %d .edf)"
                 % (path, n_dat, n_edf))
        self._refresh_buttons()
        self._say("Source opened: %d .dat and %d .edf files found. Create "
                  "Repo to convert them." % (n_dat, n_edf))

    def do_create_repo(self):
        repo = filedialog.askdirectory(
            title="Choose an EMPTY folder for the new repo")
        if not repo:
            return
        existing = [f for f in os.listdir(repo)
                    if f not in (".git", ".gitignore", ".gitattributes")]
        if existing:
            if not messagebox.askokcancel(
                    "Folder not empty",
                    "%s already contains %d item(s).\n\nCreating a repo here "
                    "will overwrite any csv/ and schemas/ already in it. "
                    "Continue?" % (repo, len(existing))):
                return
        server = self.server

        def work(progress):
            return rf_repo.create_repo(server, repo, progress=progress)

        def done(ok, result):
            if not ok:
                messagebox.showerror("Create failed", str(result))
                self._say("Create failed.")
                return
            manifest, tables, skipped = result
            self.repo = repo
            self.lbl_repo.config(text="Repo:   %s" % repo)
            self._say(
                "Created repo: %d DAT table(s), %d EDF file(s), %d skipped."
                % (len(tables), len(manifest.get("edf", {})), len(skipped)))
            self._report_skipped(tables, skipped)
            self.do_preview()

        self._run(work, done)

    def _report_skipped(self, tables, skipped):
        if not skipped:
            messagebox.showinfo(
                "Repo created",
                "All %d .dat files converted and verified." % len(tables))
            return
        reasons = {}
        for _rel, why in skipped:
            reasons[why] = reasons.get(why, 0) + 1
        lines = ["%d of %d .dat files were converted and verified.\n"
                 % (len(tables), len(tables) + len(skipped)),
                 "%d were left out, because a table only enters the repo if it "
                 "provably rebuilds to the original bytes:\n" % len(skipped)]
        for why, n in sorted(reasons.items(), key=lambda kv: -kv[1])[:8]:
            lines.append("  %d x  %s" % (n, why[:90]))
        lines.append("\nThe full list is in %s under \"skipped\"."
                     % rf_repo.MANIFEST)
        messagebox.showwarning("Repo created with gaps", "\n".join(lines))

    def do_open_repo(self):
        repo = filedialog.askdirectory(title="Select an existing repo folder")
        if not repo:
            return
        try:
            manifest = rf_repo.read_manifest(repo)
        except (SchemaError, ValueError) as e:
            messagebox.showerror("Not a repo", str(e))
            return
        self.repo = repo
        self.lbl_repo.config(text="Repo:   %s" % repo)
        if not self.server:
            self.server = manifest.get("server_root")
            self.lbl_server.config(text="Server: %s   (from the repo)"
                                        % self.server)
        if self.server and not os.path.isdir(self.server):
            messagebox.showwarning(
                "Server folder missing",
                "This repo was created from\n%s\nwhich doesn't exist right "
                "now. Use Open Server to point at it before building."
                % self.server)
        self._refresh_buttons()
        self._say("Repo opened: %d DAT table(s), %d EDF file(s). Press "
                  "Preview Changes."
                  % (len(manifest.get("tables", {})),
                     len(manifest.get("edf", {}))))
        self.do_preview()

    def do_preview(self):
        if not self.repo:
            return
        repo, server = self.repo, self.server

        def work(progress):
            return rf_repo.diff_repo(repo, server, progress=progress)

        def done(ok, result):
            if not ok:
                messagebox.showerror("Preview failed", str(result))
                self._say("Preview failed.")
                return
            self.statuses = result
            self._fill_list()
            self._refresh_buttons()
            n_ch = sum(1 for s in result if s.state == Status.CHANGED)
            n_err = sum(1 for s in result if s.state == Status.ERROR)
            self._say("Preview: %d changed, %d problem(s), %d data item(s)."
                      % (n_ch, n_err, len(result)))

        self._run(work, done)

    def _fill_list(self):
        self.tree.delete(*self.tree.get_children())
        self.diff.delete(*self.diff.get_children())
        mode = self.show_var.get()
        needle = self.filter_var.get().strip().lower()
        counts = {Status.SAME: 0, Status.CHANGED: 0, Status.ERROR: 0,
                  Status.GONE: 0}
        for s in self.statuses:
            counts[s.state] = counts.get(s.state, 0) + 1
        shown = 0
        for s in self.statuses:
            if mode == "Changed only" and s.state != Status.CHANGED:
                continue
            if mode == "Problems only" and s.state not in (Status.ERROR,
                                                           Status.GONE):
                continue
            if mode == "Changed and problems" and s.state == Status.SAME:
                continue
            if needle and needle not in s.rel.lower():
                continue
            tag = {Status.CHANGED: "changed", Status.ERROR: "error",
                   Status.GONE: "missing"}.get(s.state, "")
            self.tree.insert("", "end", iid=s.rel,
                             values=(s.rel, s.state, s.detail),
                             tags=(tag,) if tag else ())
            shown += 1
            if shown >= 2000:      # the list is for reading, not scrolling
                break
        self.lbl_counts.config(
            text="%d unchanged | %d changed | %d problems | %d missing"
                 % (counts.get(Status.SAME, 0), counts.get(Status.CHANGED, 0),
                    counts.get(Status.ERROR, 0), counts.get(Status.GONE, 0)))

    def on_select(self, _e=None):
        sel = self.tree.selection()
        self.diff.delete(*self.diff.get_children())
        if not sel:
            return
        rel = sel[0]
        s = next((x for x in self.statuses if x.rel == rel), None)
        if s is None:
            return
        if s.state == Status.ERROR:
            self.lbl_detail.config(text="%s -- won't build" % rel)
            self.diff.insert("", "end", values=("", "error", "", s.detail))
            return
        if s.state != Status.CHANGED:
            self.lbl_detail.config(text="%s -- no changes" % rel)
            return
        self.lbl_detail.config(text="%s -- %s" % (rel, s.detail))
        if s.kind == Status.FILE:
            self._show_text_diff(rel)
            return
        if s.kind == Status.EDF:
            self.diff.insert("", "end", values=(
                "", "encrypted client file", "live client", "repo build"))
            return
        try:
            changes, delta = rf_repo.field_changes(self.repo, rel, self.server)
        except (SchemaError, ValueError, OSError) as e:
            self.diff.insert("", "end", values=("", "error", "", str(e)[:120]))
            return
        if delta:
            self.diff.insert("", "end", values=(
                "", "record count",
                "%d" % (0 if delta > 0 else abs(delta)),
                "%+d record(s) in the repo" % delta))
        for rec, field, old, new in changes:
            self.diff.insert("", "end",
                             values=(rec, field, str(old)[:60], str(new)[:60]))
        if not changes and not delta:
            self.diff.insert("", "end", values=("", "(header only)", "", ""))

    def _show_text_diff(self, rel):
        """Config files diff by line, not by field."""
        try:
            rows = rf_repo.text_changes(self.repo, rel, self.server)
        except (OSError, ValueError) as e:
            self.diff.insert("", "end", values=("", "error", "", str(e)[:120]))
            return
        for lineno, tag, old, new in rows:
            self.diff.insert("", "end",
                             values=(lineno, tag, old[:90], new[:90]))
        if not rows:
            self.diff.insert("", "end",
                             values=("", "(line endings or whitespace only)",
                                     "", ""))

    def do_build(self):
        pending = [s for s in self.statuses if s.state == Status.CHANGED]
        broken = [s for s in self.statuses if s.state == Status.ERROR]
        if broken:
            messagebox.showerror(
                "Can't build",
                "%d table(s) don't build. Fix them first -- building is "
                "all-or-nothing so a half-applied change set can't happen.\n\n%s"
                % (len(broken), "\n".join(s.rel for s in broken[:10])))
            return
        if not pending:
            messagebox.showinfo("Nothing to build",
                                "The server already matches the repo.")
            return
        listing = "\n".join("  %s  (%s)" % (s.rel, s.detail)
                            for s in pending[:15])
        if len(pending) > 15:
            listing += "\n  ... and %d more" % (len(pending) - 15)
        if not messagebox.askokcancel(
                "Build to server",
                "About to overwrite %d data file(s) in\n%s\n\n%s\n\nOriginals "
                "are backed up into the repo's backups/ folder first. "
                "Continue?" % (len(pending), self.server, listing)):
            return

        repo, server = self.repo, self.server
        only = [s.rel for s in pending]

        def work(progress):
            return rf_repo.build_to_server(repo, server, only=only, apply=True,
                                           progress=progress)

        def done(ok, result):
            if not ok:
                messagebox.showerror("Build failed", str(result))
                self._say("Build failed -- nothing was written.")
                return
            written, backup = result
            messagebox.showinfo(
                "Build complete",
                "Wrote %d file(s) to the server.\n\nOriginals backed up to\n%s"
                % (len(written), backup))
            self._say("Built %d file(s). Backup: %s" % (len(written), backup))
            self.do_preview()

        self._run(work, done)


def main(argv):
    app = Workbench()
    app.mainloop()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
