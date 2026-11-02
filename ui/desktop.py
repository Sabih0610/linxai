"""Thin Linux desktop client. All planning/dispatch runs in the ordinary-user agent."""
import argparse
import json
import os
from pathlib import Path
import sys


def build_window(client, voice_model=None):
    from PySide6.QtCore import QObject, QRunnable, QThreadPool, QTimer, Signal
    from PySide6.QtWidgets import (QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QTabWidget,
                                   QLineEdit, QPushButton, QPlainTextEdit, QLabel, QTableWidget, QTableWidgetItem)

    class Signals(QObject):
        done = Signal(object)
        failed = Signal(str)

    class Call(QRunnable):
        def __init__(self, function):
            super().__init__()
            self.function, self.signals = function, Signals()
        def run(self):
            try:
                self.signals.done.emit(self.function())
            except Exception as exc:
                self.signals.failed.emit(f"{type(exc).__name__}: {str(exc)[:512]}")

    class Window(QMainWindow):
        def __init__(self):
            super().__init__()
            self.setWindowTitle("LINxAI — Linux operations")
            self.resize(1050, 740)
            self.pool, self.calls, self.preview = QThreadPool(self), set(), None
            self.pool.setMaxThreadCount(3)
            self.revision = 0
            self.tabs = QTabWidget()
            self.setCentralWidget(self.tabs)
            assistant, layout = self.page("Assistant")
            layout.addWidget(QLabel("Describe a task. Preview is required; administrative operations use trusted OS authentication."))
            self.input = QLineEdit()
            self.input.setPlaceholderText("Show memory usage / restart linxai-lab-acceptance / create file report.txt")
            layout.addWidget(self.input)
            buttons = QHBoxLayout()
            self.plan_button, self.confirm_button, self.cancel_button = QPushButton("Preview"), QPushButton("Confirm selected preview"), QPushButton("Cancel queued job")
            for button in (self.plan_button, self.confirm_button, self.cancel_button): buttons.addWidget(button)
            layout.addLayout(buttons)
            self.preview_text = QPlainTextEdit()
            self.preview_text.setReadOnly(True)
            layout.addWidget(self.preview_text)
            reconcile = QPushButton("Inspect uncertain job")
            buttons.addWidget(reconcile)
            reconcile.clicked.connect(self.reconcile)
            self.plan_button.clicked.connect(self.plan)
            self.voice_button=QPushButton("Voice input (local model)")
            buttons.addWidget(self.voice_button)
            self.voice_button.setEnabled(voice_model is not None)
            self.voice_button.clicked.connect(self.voice_input)
            self.input.returnPressed.connect(self.plan)
            self.input.textChanged.connect(self.invalidate_preview)
            self.confirm_button.clicked.connect(self.confirm)
            self.cancel_button.clicked.connect(self.cancel)
            self.confirm_button.setEnabled(False)
            _, operations = self.page("Operations")
            self.table = QTableWidget(0, 4)
            self.table.setHorizontalHeaderLabels(["Job", "Action", "State", "Operation ID"])
            self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
            operations.addWidget(self.table)
            restore=QPushButton("Preview available restoration")
            operations.addWidget(restore)
            restore.clicked.connect(self.restore_job)
            self.detail = QPlainTextEdit()
            self.detail.setReadOnly(True)
            operations.addWidget(self.detail)
            self.table.itemSelectionChanged.connect(self.selected)
            self.views = {}
            for name in ("Assets", "Security", "Activity"):
                _, pane = self.page(name)
                view = QPlainTextEdit()
                view.setReadOnly(True)
                pane.addWidget(view)
                self.views[name] = view
            assets_layout = self.tabs.widget(2).layout()
            self.asset_name = QLineEdit(); self.asset_name.setPlaceholderText("Configured asset name (development_file or Linux SSH)")
            self.interface_name = QLineEdit(); self.interface_name.setPlaceholderText("Configured interface, e.g. port1")
            assets_layout.addWidget(self.asset_name); assets_layout.addWidget(self.interface_name)
            for label,method in (("Preview development device initialization","init"),("Inspect device","inspect"),("Preview interface up","up"),("Preview interface down","down")):
                button=QPushButton(label);assets_layout.addWidget(button)
                button.clicked.connect(lambda checked=False,mode=method:self.device_action(mode))
            security_layout = self.tabs.widget(3).layout()
            self.incident_id = QLineEdit()
            self.incident_id.setPlaceholderText("Incident UUID for response, or policy UUID to revoke")
            security_layout.addWidget(self.incident_id)
            response = QPushButton("Preview bounded incident response")
            revoke = QPushButton("Preview policy revocation")
            security_layout.addWidget(response); security_layout.addWidget(revoke)
            response.clicked.connect(lambda: self.security_preview("propose_response", "incident_id"))
            revoke.clicked.connect(lambda: self.security_preview("revoke_policy", "policy_id"))
            for label,action in (("Preview face enrollment (password required)","auth.face.enroll"),("Preview face revocation","auth.face.revoke")):
                button=QPushButton(label);security_layout.addWidget(button)
                button.clicked.connect(lambda checked=False,action=action:self.call(lambda:client.call("typed_preview",request={"action":action,"parameters":{}}),self.show_preview))
            self.face_challenge=QLabel("Face primary remains disabled until protected lab qualification")
            security_layout.addWidget(self.face_challenge)
            self.status = QLabel("Connecting to the local agent; no model or privileged component is started by this window")
            self.statusBar().addWidget(self.status)
            self.refreshing = False
            self.timer = QTimer(self)
            self.timer.timeout.connect(self.refresh)
            self.timer.start(1500)
            self.refresh()

        def page(self, name):
            page = QWidget()
            layout = QVBoxLayout(page)
            self.tabs.addTab(page, name)
            return page, layout

        def call(self, function, complete):
            if len(self.calls) >= 8:
                self.status.setText("Request queue busy; wait for the current request")
                return
            work = Call(function)
            self.calls.add(work)
            def done(value):
                self.calls.discard(work)
                complete(value)
            def failed(reason):
                self.calls.discard(work)
                self.refreshing = False
                self.status.setText(reason + "; start linxai-agent as your ordinary account if it is unavailable")
            work.signals.done.connect(done)
            work.signals.failed.connect(failed)
            self.pool.start(work)

        def show_preview(self,row):
            self.preview=row
            self.preview_text.setPlainText(json.dumps(row,indent=2)[:65536])
            self.confirm_button.setEnabled(True);self.tabs.setCurrentIndex(0)

        def device_action(self,mode):
            asset=self.asset_name.text();interface=self.interface_name.text()
            if mode=="inspect":
                self.call(lambda:client.call("device_inspect",asset=asset),lambda row:self.views["Assets"].setPlainText(json.dumps(row,indent=2)[:65536]))
            elif mode=="init":
                self.call(lambda:client.call("typed_preview",request={"action":"device.initialize","parameters":{"asset":asset}}),self.show_preview)
            else:
                self.call(lambda:client.call("device_preview",asset=asset,interface=interface,enabled=mode=="up"),self.show_preview)

        def security_preview(self, method, field):
            key = self.incident_id.text()
            def show(row):
                self.preview = row
                self.preview_text.setPlainText(json.dumps(row,indent=2)[:65536])
                self.confirm_button.setEnabled(True)
                self.tabs.setCurrentIndex(0)
            self.call(lambda: client.call(method, **{field:key}), show)

        def invalidate_preview(self):
            self.revision += 1
            self.preview = None
            self.confirm_button.setEnabled(False)

        def voice_input(self):
            self.invalidate_preview()
            self.status.setText("Listening; local capture/transcription has a 45 second deadline")
            from voice.client import listen
            revision = self.revision
            def captured(text):
                if revision != self.revision: return
                self.input.setText(text)
                self.plan()
            self.call(lambda:listen(voice_model),captured)

        def plan(self):
            text = self.input.text()
            revision = self.revision
            self.confirm_button.setEnabled(False)
            self.preview = None
            def preview(value):
                if revision != self.revision: return
                self.preview = value
                self.preview_text.setPlainText(json.dumps(value, indent=2)[:65536])
                self.confirm_button.setEnabled(True)
                self.status.setText("Preview ready. Mandatory system checks run again at dispatch.")
            self.call(lambda: client.call("preview", text=text), preview)

        def confirm(self):
            if not self.preview: return
            row = self.preview
            self.confirm_button.setEnabled(False)
            self.preview = None
            self.call(lambda: client.call("confirm", id=row["id"], digest=row["digest"]),
                      lambda result: self.status.setText("Queued job " + result["id"]))

        def cancel(self):
            key = self.preview["id"] if self.preview else self.selected_id()
            if key:
                self.call(lambda: client.call("cancel", id=key), lambda row: self.status.setText("Cancellation state: " + row["state"]))

        def restore_job(self):
            key=self.selected_id()
            if key:self.call(lambda:client.call("restore_job",id=key),self.show_preview)

        def reconcile(self):
            key = self.selected_id()
            if key:
                self.call(lambda: client.call("reconcile", id=key), lambda row: self.detail.setPlainText(json.dumps(row, indent=2)[:65536]))

        def selected_id(self):
            row = self.table.currentRow()
            return self.table.item(row, 0).text() if row >= 0 and self.table.item(row, 0) else None

        def selected(self):
            key = self.selected_id()
            if key:
                self.call(lambda: client.call("job", id=key), lambda row: self.detail.setPlainText(json.dumps(row, indent=2)[:65536]))

        def refresh(self):
            if self.refreshing: return
            self.refreshing = True
            def read():
                return client.call("jobs"), client.call("status"), client.call("security")
            def render(value):
                self.refreshing = False
                jobs, status, security = value
                pending=status.get("face",{}).get("pending")
                self.face_challenge.setText(("Requested "+pending["label"]+": "+", ".join(pending["sequence"])) if pending else "No active camera challenge; trusted OS password fallback is available")
                selected = self.selected_id()
                self.table.blockSignals(True)
                self.table.setRowCount(len(jobs["jobs"]))
                for index, row in enumerate(jobs["jobs"]):
                    for column, field in enumerate((row["id"], row["action"], row["state"], row.get("operation_id", ""))):
                        self.table.setItem(index, column, QTableWidgetItem(str(field)))
                    if row["id"] == selected: self.table.selectRow(index)
                self.table.blockSignals(False)
                self.table.resizeColumnsToContents()
                self.views["Assets"].setPlainText(json.dumps(status, indent=2))
                self.views["Security"].setPlainText(json.dumps(security, indent=2)[:65536])
                self.views["Activity"].setPlainText(json.dumps(jobs, indent=2)[:65536])
                if selected: self.selected()
                self.status.setText("Agent connected. Closing this window leaves admitted jobs and monitoring independent.")
            self.call(read, render)

    return Window()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--socket", type=Path)
    parser.add_argument("--voice-model",type=Path,help="Explicit existing local Whisper model; no download")
    args = parser.parse_args(argv)
    from operations.supervised import SupervisedLinuxAdapter
    if not SupervisedLinuxAdapter().resolve_identity().ordinary():
        raise PermissionError("Desktop requires ordinary Linux identity")
    try:
        from PySide6.QtWidgets import QApplication
    except ImportError:
        print("Install the pinned desktop profile: sh install.sh --desktop", file=sys.stderr)
        return 2
    from operations.agent import AgentClient
    application = QApplication(sys.argv[:1])
    window = build_window(AgentClient(args.socket),args.voice_model)
    window.show()
    return application.exec()


if __name__ == "__main__":
    raise SystemExit(main())
