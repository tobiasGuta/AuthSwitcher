# -*- coding: utf-8 -*-
# AuthSwitcher_UI.py
# Jython Burp extension implementing the UI diagram the user requested:
# Top controls for header/profile input, middle table of captured originals,
# bottom side-by-side original vs duplicate request+response viewer (no footer).
#
# Drop into Burp Extender (select Python/Jython). Tested pattern-wise against Burp API.
# Note: This is an MVP; for production/hardening add rate-limiting, persistence, and robust error handling.

from burp import IBurpExtender, IHttpListener, IExtensionHelpers, ITab, IMessageEditorController
from java.io import PrintWriter
from java.lang import Object, Runnable
from javax import swing
from javax.swing import JTable, JScrollPane, JSplitPane, JTabbedPane, JTextArea, JComboBox, JLabel, JButton, JPanel, JCheckBox, JTextField, JList, DefaultListModel, JOptionPane
from javax.swing.table import AbstractTableModel
from java.awt import BorderLayout, GridLayout, Dimension, Font, FlowLayout
from java.awt.event import MouseAdapter, MouseEvent, ActionListener
from javax.swing.event import ChangeListener
import threading
import re
import time

# Small helper proxies that implement the actual Java interfaces
class PyActionListener(ActionListener):
    def __init__(self, func):
        self.func = func
    def actionPerformed(self, event):
        try:
            self.func(event)
        except:
            pass

class PyChangeListener(ChangeListener):
    def __init__(self, func):
        self.func = func
    def stateChanged(self, event):
        try:
            self.func(event)
        except:
            pass

class PyRunnable(Runnable):
    def __init__(self, func):
        self.func = func
    def run(self):
        try:
            self.func()
        except:
            pass

class RequestEntry(object):
    def __init__(self, id, timestamp, httpService, headers, body, original_rr):
        self.id = id
        self.timestamp = timestamp
        self.httpService = httpService
        self.headers = headers  # list of header lines (including request line)
        self.body = body  # byte[] or string (we'll store as bytes)
        self.original_rr = original_rr
        self.duplicates = {}  # profileName -> DuplicateEntry

class DuplicateEntry(object):
    def __init__(self, profileName, request_bytes, response_bytes, status, rt_ms, timestamp):
        self.profileName = profileName
        self.request_bytes = request_bytes
        self.response_bytes = response_bytes
        self.status = status
        self.rt_ms = rt_ms
        self.timestamp = timestamp

class RequestTableModel(AbstractTableModel):
    def __init__(self, entries):
        self.entries = entries
        # show URL / status / length as requested (Profiles column removed)
        self.cols = ["#", "Time", "Method", "URL", "Status", "Length"]
    def getRowCount(self):
        return len(self.entries)
    def getColumnCount(self):
        return len(self.cols)
    def getColumnName(self, idx):
        return self.cols[idx]
    def getValueAt(self, row, col):
        e = self.entries[row]
        if col == 0:
            return str(e.id)
        elif col == 1:
            return time.strftime("%H:%M:%S", time.localtime(e.timestamp))
        else:
            # parse request line
            req_line = e.headers[0] if e.headers else ""
            try:
                parts = req_line.split()
                method = parts[0] if len(parts)>0 else ""
                path = parts[1] if len(parts)>1 else ""
            except:
                method = ""
                path = ""
            if col == 2:
                return method
            elif col == 3:
                # URL-like: host + path
                try:
                    host = e.httpService.getHost()
                    port = e.httpService.getPort()
                    proto = e.httpService.getProtocol()
                    # build a concise URL for display
                    return "%s://%s%s" % (proto, host, path)
                except:
                    return "%s%s" % (e.httpService.getHost(), path)
            elif col == 4:
                # status of original response
                try:
                    resp = e.original_rr.getResponse()
                    if not resp:
                        return "-"
                    return str(helpers.analyzeResponse(resp).getStatusCode())
                except:
                    return "-"
            elif col == 5:
                # length (bytes) of original response
                try:
                    resp = e.original_rr.getResponse()
                    if not resp:
                        return "0"
                    return str(len(resp))
                except:
                    return "-"
            # Profiles column removed

        return ""
    # needed by JTable
    def isCellEditable(self, r,c):
        return False

class BurpExtender(IBurpExtender, IHttpListener, ITab, IMessageEditorController):
    def registerExtenderCallbacks(self, callbacks):
        import traceback
        global helpers
        self.callbacks = callbacks
        helpers = callbacks.getHelpers()
        self._stdout = PrintWriter(callbacks.getStdout(), True)
        self._stderr = PrintWriter(callbacks.getStderr(), True)

        self._stdout.println("AuthSwitcherUI: registerExtenderCallbacks start")
        try:
            callbacks.setExtensionName("AuthSwitcherUI")
        except Exception as e:
            self._stderr.println("AuthSwitcherUI: setExtensionName failed: %s" % str(e))

        # State
        self.enabled = True
        self.header_name = "Cookie"
        self.original_header_value_match = None
        self.profiles = {}
        self.scope_regex = ".*"
        self.duplicate_only_in_scope = True
        # marker header added to duplicated requests so we can ignore them and avoid loops
        self.dup_marker = "X-AuthSwitcher-Dup"

        # Captured entries
        self.entries = []
        self.next_id = 1

        # Setup UI
        try:
            # Build UI and register tab on the Swing EDT (creates Swing components on the correct thread)
            def _build_and_register():
                try:
                    # build the UI on the EDT
                    self._init_ui()
                    self._stdout.println("AuthSwitcherUI: UI init OK (EDT)")
                except Exception:
                    import traceback
                    traceback.print_exc(file=self._stderr)
                    self._stderr.println("AuthSwitcherUI: UI init failed (EDT)")
                    return

                try:
                    callbacks.addSuiteTab(self)
                    self._stdout.println("AuthSwitcherUI: addSuiteTab succeeded")
                except Exception:
                    import traceback
                    traceback.print_exc(file=self._stderr)
                    self._stderr.println("AuthSwitcherUI: addSuiteTab failed")

            try:
                # ensure we pass a Runnable proxy to invokeLater
                swing.SwingUtilities.invokeLater(PyRunnable(_build_and_register))
            except Exception:
                # fallback: run synchronously if invokeLater isn't available
                _build_and_register()
        except Exception as e:
            traceback.print_exc(file=self._stderr)
            self._stderr.println("AuthSwitcherUI: UI init failed: %s" % str(e))

        # NOTE: _build_and_register runs on the Swing EDT via invokeLater (async),
        # so don't check for self._panel here (it may not be created yet).

        # Register HTTP listener
        try:
            callbacks.registerHttpListener(self)
            self._stdout.println("AuthSwitcherUI: HTTP listener registered")
        except Exception as e:
            traceback.print_exc(file=self._stderr)
            self._stderr.println("AuthSwitcherUI: registerHttpListener failed: %s" % str(e))

        self._stdout.println("AuthSwitcherUI: registerExtenderCallbacks done")

    def _init_ui(self):
        # Full-featured UI per user's diagram
        root = JPanel(BorderLayout())

        # --- TOP CONTROLS --- (compact / improved spacing)
        top = JPanel(BorderLayout())
        controls = JPanel(FlowLayout(FlowLayout.LEFT, 6, 6))
        controls.add(JLabel("Credentials:"))
        self.header_combo = JComboBox(["Cookie", "Authorization", "X-Auth-Token", "X-API-Key", "Custom"])
        # keep combo compact
        try:
            self.header_combo.setPreferredSize(Dimension(160, 24))
        except:
            pass
        def on_header_change(evt=None):
            sel = self.header_combo.getSelectedItem()
            try:
                if sel == "Custom":
                    h = JOptionPane.showInputDialog(None, "Enter custom header name (e.g. New_Cookie):")
                    if h and h.strip():
                        self.header_name = h.strip()
                    else:
                        try:
                            self.header_combo.setSelectedItem(self.header_name if self.header_name in ["Cookie", "Authorization", "X-Auth-Token", "X-API-Key"] else "Custom")
                        except:
                            pass
                else:
                    if sel:
                        self.header_name = sel
            except:
                pass
        self.header_combo.addActionListener(PyActionListener(on_header_change))
        controls.add(self.header_combo)
        self.tf_cred = JTextField()
        try:
            self.tf_cred.setPreferredSize(Dimension(420, 24))
        except:
            pass
        self.tf_cred.setToolTipText("Enter header value (or paste 'Header: value')")
        controls.add(self.tf_cred)
        # small "Send" convenience button (manual trigger) — compact and optional
        send_btn = JButton("Send")
        def send_now(evt=None):
            # duplicate selected row(s) using tf_cred as fallback profile
            rows = self.table.getSelectedRows()
            if not rows:
                JOptionPane.showMessageDialog(None, "Select one or more rows to duplicate")
                return
            def _profiles_from_ui():
                profiles = list(self.profiles.items())
                header_override = None
                if not profiles:
                    raw = getattr(self, "tf_cred", None) and self.tf_cred.getText().strip() or ""
                    if raw:
                        if ":" in raw:
                            parts = raw.split(":",1)
                            maybe_header = parts[0].strip()
                            val = parts[1].strip()
                            header_override = maybe_header
                            profiles = [("Manual", val)]
                        else:
                            profiles = [("Manual", raw)]
                return profiles, header_override
            for r in rows:
                if r < 0 or r >= len(self.entries): continue
                entry = self.entries[r]
                profiles_to_use, header_override = _profiles_from_ui()
                if not profiles_to_use:
                    JOptionPane.showMessageDialog(None, "No profiles configured and credential field is empty")
                    return
                for pname, pval in profiles_to_use[:getattr(self, "max_duplicates", 4)]:
                    msg = self._build_duplicate_message(entry.headers, entry.body, pval, header_override=header_override)
                    threading.Thread(target=self._send_duplicate_and_store, args=(entry.httpService, msg, entry, pname)).start()
        send_btn.addActionListener(PyActionListener(send_now))
        controls.add(send_btn)

        # Right-aligned compact scope/settings
        settings = JPanel(FlowLayout(FlowLayout.RIGHT, 8, 6))
        settings.add(JLabel("Scope:"))
        self.tf_scope = JTextField(self.scope_regex)
        try:
            self.tf_scope.setPreferredSize(Dimension(200, 24))
        except:
            pass
        self.tf_scope.setToolTipText("Host or regex to limit processing")
        def scope_changed(evt=None):
            self.scope_regex = self.tf_scope.getText().strip() or ".*"
        self.tf_scope.addActionListener(PyActionListener(scope_changed))
        settings.add(self.tf_scope)
        self.enabled_chk = JCheckBox("Enabled", True)
        def enabled_changed(evt=None):
            self.enabled = self.enabled_chk.isSelected()
        self.enabled_chk.addActionListener(PyActionListener(enabled_changed))
        settings.add(self.enabled_chk)
        # compact checkboxes and spinner
        self.auto_dup_chk = JCheckBox("Auto-dup", True)
        settings.add(self.auto_dup_chk)
        self.only_when_orig_chk = JCheckBox("Only if orig", True)
        settings.add(self.only_when_orig_chk)
        spinner = swing.JSpinner(swing.SpinnerNumberModel(4, 1, 20, 1))
        try:
            spinner.setPreferredSize(Dimension(60, 24))
        except:
            pass
        def spinner_changed(evt=None):
            try:
                self.max_duplicates = int(spinner.getValue())
            except:
                self.max_duplicates = 4
        spinner.addChangeListener(PyChangeListener(lambda e: spinner_changed()))
        settings.add(JLabel("Max:"))
        settings.add(spinner)

        top.add(controls, BorderLayout.CENTER)
        top.add(settings, BorderLayout.EAST)
        try:
            top.setPreferredSize(Dimension(1200, 44))
        except:
            pass
        root.add(top, BorderLayout.NORTH)

        # --- MIDDLE: Table of captured requests ---
        center_panel = JPanel(BorderLayout())
        # Profiles list removed from left column (profiles are managed from top controls)
        # no WEST component on center_panel

        # Table
        self.table_model = RequestTableModel(self.entries)
        self.table = JTable(self.table_model)
        # multi-select rows
        self.table.setSelectionMode(swing.ListSelectionModel.MULTIPLE_INTERVAL_SELECTION)
        self.table.setPreferredScrollableViewportSize(Dimension(1000, 180))
        # reasonable default column widths
        try:
            cm = self.table.getColumnModel()
            cm.getColumn(0).setPreferredWidth(40)   # #
            cm.getColumn(1).setPreferredWidth(90)   # Time
            cm.getColumn(2).setPreferredWidth(60)   # Method
            cm.getColumn(3).setPreferredWidth(300)  # URL/path
            cm.getColumn(4).setPreferredWidth(80)   # Status
            cm.getColumn(5).setPreferredWidth(120)  # Length
        except:
            pass
        # Context menu
        popup = swing.JPopupMenu()
        mi_dup_now = swing.JMenuItem("Duplicate now")
        def do_dup_now(evt=None):
            rows = self.table.getSelectedRows()
            if not rows:
                JOptionPane.showMessageDialog(None, "Select one or more rows to duplicate")
                return
            # determine profiles to use (fallback to current credential field when no saved profiles)
            def _profiles_from_ui():
                profiles = list(self.profiles.items())
                header_override = None
                if not profiles:
                    raw = getattr(self, "tf_cred", None) and self.tf_cred.getText().strip() or ""
                    if raw:
                        if ":" in raw:
                            parts = raw.split(":",1)
                            maybe_header = parts[0].strip()
                            val = parts[1].strip()
                            header_override = maybe_header
                            profiles = [("Manual", val)]
                        else:
                            profiles = [("Manual", raw)]
                return profiles, header_override

            for r in rows:
                if r < 0 or r >= len(self.entries):
                    continue
                entry = self.entries[r]
                profiles_to_use, header_override = _profiles_from_ui()
                if not profiles_to_use:
                    JOptionPane.showMessageDialog(None, "No profiles configured and credential field is empty")
                    return
                count = 0
                for pname, pval in profiles_to_use:
                    if count >= getattr(self, "max_duplicates", 4):
                        break
                    msg = self._build_duplicate_message(entry.headers, entry.body, pval, header_override=header_override)
                    threading.Thread(target=self._send_duplicate_and_store, args=(entry.httpService, msg, entry, pname)).start()
                    count += 1
        mi_dup_now.addActionListener(PyActionListener(do_dup_now))
        popup.add(mi_dup_now)

        mi_view_diffs = swing.JMenuItem("View diffs (not implemented)")
        mi_view_diffs.addActionListener(PyActionListener(lambda e: JOptionPane.showMessageDialog(None, "View diffs not implemented")))
        popup.add(mi_view_diffs)

        mi_open_repeater = swing.JMenuItem("Open in Repeater (send request)")
        def open_in_repeater(evt=None):
            rows = self.table.getSelectedRows()
            if not rows:
                JOptionPane.showMessageDialog(None, "Select a row")
                return
            # send first selected to Repeater via callbacks
            r = rows[0]
            if r < 0 or r >= len(self.entries):
                return
            entry = self.entries[r]
            try:
                req = helpers.buildHttpMessage(entry.headers, entry.body)
                # send to Repeater via callbacks - use sendToRepeater if available
                try:
                    self.callbacks.sendToRepeater(entry.httpService.getHost(), entry.httpService.getPort(), entry.httpService.getProtocol()=="https", req)
                    JOptionPane.showMessageDialog(None, "Sent to Repeater")
                except:
                    # fallback: show not implemented
                    JOptionPane.showMessageDialog(None, "sendToRepeater not available in this environment")
            except Exception as ex:
                JOptionPane.showMessageDialog(None, "Error opening in Repeater: %s" % str(ex))
        mi_open_repeater.addActionListener(PyActionListener(open_in_repeater))
        popup.add(mi_open_repeater)

        mi_export = swing.JMenuItem("Export request")
        def export_req(evt=None):
            rows = self.table.getSelectedRows()
            if not rows:
                JOptionPane.showMessageDialog(None, "Select a row")
                return
            r = rows[0]
            entry = self.entries[r]
            chooser = swing.JFileChooser()
            res = chooser.showSaveDialog(None)
            if res == swing.JFileChooser.APPROVE_OPTION:
                f = chooser.getSelectedFile()
                try:
                    with open(str(f.getAbsolutePath()), "wb") as fh:
                        fh.write(helpers.bytesToString(helpers.buildHttpMessage(entry.headers, entry.body)).encode("utf-8"))
                    JOptionPane.showMessageDialog(None, "Exported")
                except Exception as ex:
                    JOptionPane.showMessageDialog(None, "Error exporting: %s" % str(ex))
        mi_export.addActionListener(PyActionListener(export_req))
        popup.add(mi_export)

        mi_toggle_watch = swing.JMenuItem("Toggle watch")
        def toggle_watch(evt=None):
            rows = self.table.getSelectedRows()
            for r in rows:
                if r < 0 or r >= len(self.entries): continue
                entry = self.entries[r]
                entry.watched = not getattr(entry, "watched", False)
            self.table_model.fireTableDataChanged()
        mi_toggle_watch.addActionListener(PyActionListener(toggle_watch))
        popup.add(mi_toggle_watch)

        # Delete selected entry/entries
        mi_delete = swing.JMenuItem("Delete selected")
        def delete_selected(evt=None):
            rows = self.table.getSelectedRows()
            if not rows:
                return
            # delete rows in reverse order so indices remain valid
            try:
                for r in sorted(rows, reverse=True):
                    if 0 <= r < len(self.entries):
                        del self.entries[r]
                # clear editors and controller state if necessary
                try:
                    self.left_req_editor.setMessage(None, True)
                    self.left_resp_editor.setMessage(None, False)
                    self.right_req_editor.setMessage(None, True)
                    self.right_resp_editor.setMessage(None, False)
                except:
                    pass
                self._editor_request = None
                self._editor_response = None
                self._editor_httpService = None
                self.table_model.fireTableDataChanged()
            except Exception as ex:
                self._stderr.println("Error deleting selected: %s" % str(ex))
        mi_delete.addActionListener(PyActionListener(delete_selected))
        popup.add(mi_delete)

        # Clear all history
        mi_clear = swing.JMenuItem("Clear history")
        def clear_history(evt=None):
            ans = JOptionPane.showConfirmDialog(None, "Clear all captured entries?", "Confirm", JOptionPane.YES_NO_OPTION)
            if ans != JOptionPane.YES_OPTION:
                return
            try:
                self.entries = []
                self.next_id = 1
                # ensure model references the new list
                self.table_model.entries = self.entries
                try:
                    self.left_req_editor.setMessage(None, True)
                    self.left_resp_editor.setMessage(None, False)
                    self.right_req_editor.setMessage(None, True)
                    self.right_resp_editor.setMessage(None, False)
                except:
                    pass
                self._editor_request = None
                self._editor_response = None
                self._editor_httpService = None
                self.table_model.fireTableDataChanged()
            except Exception as ex:
                self._stderr.println("Error clearing history: %s" % str(ex))
        mi_clear.addActionListener(PyActionListener(clear_history))
        popup.add(mi_clear)

        # attach mouse listener for popup and selection -> populate detail
        def on_table_mouse(evt):
            if evt.isPopupTrigger():
                popup.show(evt.getComponent(), evt.getX(), evt.getY())
            else:
                # selection change
                sel = self.table.getSelectedRow()
                if sel >= 0:
                    self._populate_detail_for_row(sel)
        class TableMouse(MouseAdapter):
            def mouseClicked(self, e): on_table_mouse(e)
            def mousePressed(self, e): on_table_mouse(e)
            def mouseReleased(self, e): on_table_mouse(e)
        self.table.addMouseListener(TableMouse())

        table_panel = JPanel(BorderLayout())
        table_panel.add(JScrollPane(self.table), BorderLayout.CENTER)
        center_panel.add(table_panel, BorderLayout.CENTER)

        root.add(center_panel, BorderLayout.CENTER)

        # --- BOTTOM: Detail / Repeater style side-by-side view ---
        bottom_split = JSplitPane(JSplitPane.HORIZONTAL_SPLIT)
        # ensure equal weight between left and right panes and let JSplitPane manage resizing
        try:
            bottom_split.setResizeWeight(0.5)
        except:
            pass

        # Left original: use Burp IMessageEditor so appearance/behaviour matches Repeater
        left_tabs = JTabbedPane()
        # create message editors via callbacks so they have Repeater look/formatting
        self.left_req_editor = self.callbacks.createMessageEditor(self, False)
        self.left_resp_editor = self.callbacks.createMessageEditor(self, False)
        # prefer larger sizes for editors
        try:
            self.left_req_editor.setPreferredSize(Dimension(900, 480))
            self.left_resp_editor.setPreferredSize(Dimension(900, 480))
        except:
            pass
        left_tabs.addTab("Request", self.left_req_editor.getComponent())
        left_tabs.addTab("Response", self.left_resp_editor.getComponent())

        # Right duplicate: use Burp IMessageEditor for identical Repeater style
        right_panel = JPanel(BorderLayout())
        right_tabs = JTabbedPane()
        self.right_req_editor = self.callbacks.createMessageEditor(self, False)
        self.right_resp_editor = self.callbacks.createMessageEditor(self, False)
        try:
            self.right_req_editor.setPreferredSize(Dimension(900, 480))
            self.right_resp_editor.setPreferredSize(Dimension(900, 480))
        except:
            pass
        right_tabs.addTab("Request", self.right_req_editor.getComponent())
        right_tabs.addTab("Response", self.right_resp_editor.getComponent())
        right_panel.add(right_tabs, BorderLayout.CENTER)

        bottom_split.setLeftComponent(left_tabs)
        bottom_split.setRightComponent(right_panel)
        # prefer equal-sized left/right panes inside the bottom area
        try:
            bottom_split.setResizeWeight(0.5)
            bottom_split.setOneTouchExpandable(True)
        except:
            pass
        # request/response area should be larger overall: hint preferred size for bottom area
        try:
            bottom_split.setPreferredSize(Dimension(1200, 480))
            bottom_split.setMinimumSize(Dimension(600, 200))
        except:
            pass

        root.add(bottom_split, BorderLayout.SOUTH)

        # action when duplicate profile changes
        def dup_profile_changed(evt=None):
            sel_row = self.table.getSelectedRow()
            if sel_row >= 0:
                self._populate_detail_for_row(sel_row)
        # (duplicate-profile UI removed — right pane will show the first available duplicate if present)

        # store panel for ITab
        self._panel = root

    #
    # IMessageEditorController implementation (required by createMessageEditor)
    #
    def getHttpService(self):
        return getattr(self, "_editor_httpService", None)

    def getRequest(self):
        # return currently-set request bytes for the active editor (or None)
        return getattr(self, "_editor_request", None)

    def getResponse(self):
        return getattr(self, "_editor_response", None)

    # ITab implementation
    def getTabCaption(self):
        return "AuthSwitcher"

    def getUiComponent(self):
        return self._panel

    def _refresh_profile_list(self):
        # Profile list UI removed; nothing to update here.
        return

    def _populate_detail_for_row(self, row_idx):
        if row_idx < 0 or row_idx >= len(self.entries):
            return
        entry = self.entries[row_idx]

        # show original request using Burp message editor (Repeater style)
        try:
            req_bytes = helpers.buildHttpMessage(entry.headers, entry.body)
            self._editor_httpService = entry.httpService
            self._editor_request = req_bytes
            # original request (isRequest=True)
            self.left_req_editor.setMessage(req_bytes, True)
        except Exception as e:
            # fallback: clear editor
            try:
                self.left_req_editor.setMessage(None, True)
            except:
                pass

        # show original response (if any) using message editor (isRequest=False)
        try:
            resp_bytes = entry.original_rr.getResponse()
            self._editor_response = resp_bytes
            if resp_bytes:
                self.left_resp_editor.setMessage(resp_bytes, False)
            else:
                self.left_resp_editor.setMessage(None, False)
        except Exception as e:
            try:
                self.left_resp_editor.setMessage(None, False)
            except:
                pass

        # duplicate side: pick first available duplicate profile (if any)
        selected_profile = None
        try:
            keys = sorted(entry.duplicates.keys())
            if keys:
                selected_profile = keys[0]
        except:
            selected_profile = None

        # populate right editors from duplicate entry if exists (Repeater-style editors)
        if selected_profile and selected_profile in entry.duplicates:
            d = entry.duplicates[selected_profile]
            try:
                if d.request_bytes:
                    self.right_req_editor.setMessage(d.request_bytes, True)
                else:
                    self.right_req_editor.setMessage(None, True)
            except:
                try:
                    self.right_req_editor.setMessage(None, True)
                except:
                    pass
            try:
                if d.response_bytes:
                    self.right_resp_editor.setMessage(d.response_bytes, False)
                else:
                    self.right_resp_editor.setMessage(None, False)
            except:
                try:
                    self.right_resp_editor.setMessage(None, False)
                except:
                    pass
        else:
            try:
                self.right_req_editor.setMessage(None, True)
                self.right_resp_editor.setMessage(None, False)
            except:
                pass

    #
    # IHttpListener implementation
    #
    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        try:
            # Common data
            httpService = messageInfo.getHttpService()
            host = httpService.getHost()
            port = httpService.getPort()
            proto = httpService.getProtocol()
            url_like = "%s:%s" % (host, port)

            # If this is a response event, try to find the matching entry and update UI
            if not messageIsRequest:
                if self.duplicate_only_in_scope:
                    if not re.search(self.scope_regex, url_like) and not re.search(self.scope_regex, host):
                        return
                # Try identity match first (the messageInfo object stored at request time will be updated by Burp)
                match_idx = None
                for idx, entry in enumerate(self.entries):
                    try:
                        if entry.original_rr is messageInfo:
                            match_idx = idx
                            break
                    except:
                        pass
                # fallback: match by request bytes
                if match_idx is None:
                    try:
                        resp_req = messageInfo.getRequest()
                        for idx, entry in enumerate(self.entries):
                            try:
                                b = helpers.buildHttpMessage(entry.headers, entry.body)
                                if b == resp_req:
                                    match_idx = idx
                                    break
                            except:
                                pass
                    except:
                        pass

                if match_idx is not None:
                    # store the response-bearing messageInfo on the matched entry so getResponse() works later
                    try:
                        self.entries[match_idx].original_rr = messageInfo
                    except:
                        pass
                    def refresh_ui():
                        self.table_model.fireTableDataChanged()
                        sel = self.table.getSelectedRow()
                        if sel >= 0 and sel < len(self.entries) and self.entries[sel].id == self.entries[match_idx].id:
                            self._populate_detail_for_row(sel)
                    swing.SwingUtilities.invokeLater(refresh_ui)
                return

            # --- request event handling (existing logic) ---
            if not self.enabled:
                return
            if self.duplicate_only_in_scope:
                if not re.search(self.scope_regex, url_like) and not re.search(self.scope_regex, host):
                    return

            request = messageInfo.getRequest()
            analyzed = helpers.analyzeRequest(httpService, request)
            headers = list(analyzed.getHeaders())
            body_offset = analyzed.getBodyOffset()
            body = request[body_offset:]

            # Skip requests that were created by this extension (avoid duplication loop)
            try:
                for h in headers:
                    if h.lower().startswith(self.dup_marker.lower() + ":"):
                        return
            except:
                pass

            # If the user asked to only duplicate when the original header is present,
            # skip requests that don't contain the header. If the checkbox is unchecked,
            # capture all requests (useful when Proxy is running).
            header_lower = self.header_name.lower()
            header_present = False
            header_value_in_request = None
            for h in headers:
                if h.lower().startswith(header_lower + ":"):
                    header_present = True
                    header_value_in_request = h.split(":",1)[1].strip()
                    break
            if not header_present and getattr(self, "only_when_orig_chk", None) and self.only_when_orig_chk.isSelected():
                return

            # Build entry and store
            entry_id = self.next_id
            self.next_id += 1
            entry = RequestEntry(entry_id, time.time(), httpService, headers, body, messageInfo)
            self.entries.append(entry)

            # Update table UI on EDT
            def refresh_table():
                self.table_model.fireTableDataChanged()
            swing.SwingUtilities.invokeLater(refresh_table)

            # Auto-duplicate only when checkbox selected
            if not getattr(self, "auto_dup_chk", None) or not self.auto_dup_chk.isSelected():
                return

            # determine profiles to use (fallback to current credential field when no saved profiles)
            profiles_to_use = list(self.profiles.items())
            header_override = None
            if not profiles_to_use:
                raw = getattr(self, "tf_cred", None) and self.tf_cred.getText().strip() or ""
                if raw:
                    if ":" in raw:
                        parts = raw.split(":",1)
                        maybe_header = parts[0].strip()
                        val = parts[1].strip()
                        header_override = maybe_header
                        profiles_to_use = [("Manual", val)]
                    else:
                        profiles_to_use = [("Manual", raw)]

            # For each profile, build duplicate request replacing the header value and send it
            for pname, pval in profiles_to_use:
                msg = self._build_duplicate_message(headers, body, pval, header_override=header_override)
                threading.Thread(target=self._send_duplicate_and_store, args=(httpService, msg, entry, pname)).start()

        except Exception as e:
            self._stderr.println("processHttpMessage err: %s" % str(e))

    def _send_duplicate_and_store(self, httpService, message, entry, profileName):
        try:
            t0 = time.time()
            rr = self.callbacks.makeHttpRequest(httpService, message)
            t1 = time.time()
            rt_ms = int((t1 - t0) * 1000)
            resp = rr.getResponse()
            status = "-"
            if resp:
                try:
                    status = str(helpers.analyzeResponse(resp).getStatusCode())
                except:
                    status = "-"
            dup = DuplicateEntry(profileName, message, resp, status, rt_ms, time.time())
            entry.duplicates[profileName] = dup
            # refresh UI: table (profiles column), and if selected row is this entry show duplicate in bottom pane
            def refresh_ui():
                self.table_model.fireTableDataChanged()
                # if this entry is selected row, repopulate detail
                sel = self.table.getSelectedRow()
                if sel >= 0 and sel < len(self.entries) and self.entries[sel].id == entry.id:
                    # refresh UI and repopulate detail if this entry is selected
                    self._populate_detail_for_row(sel)
            swing.SwingUtilities.invokeLater(refresh_ui)
            self._stdout.println("[AuthSwitcherUI] dup sent profile=%s status=%s rt=%dms id=%d" % (profileName, status, rt_ms, entry.id))
        except Exception as e:
            self._stderr.println("Error sending duplicate: %s" % str(e))

    def _build_duplicate_message(self, headers, body, profile_value, header_override=None):
        """
        Create a duplicate HTTP message bytes replacing or inserting the configured header.
        Insert after Host header if Host exists, otherwise after the request line.
        """
        headers_copy = list(headers)
        # allow overriding the header name for this call
        header_name = header_override if header_override else self.header_name
        header_lower = header_name.lower()
        did_replace = False
        for i, h in enumerate(headers_copy):
            if h.lower().startswith(header_lower + ":"):
                headers_copy[i] = "%s: %s" % (header_name, profile_value)
                did_replace = True
                break
        if not did_replace:
            # Prefer inserting after Host header so Cookie/Authorization ends up in the normal place
            host_idx = None
            for i, h in enumerate(headers_copy):
                if h.lower().startswith("host:"):
                    host_idx = i
                    break
            insert_idx = host_idx + 1 if host_idx is not None else 1
            headers_copy.insert(insert_idx, "%s: %s" % (header_name, profile_value))
        # add marker so this duplicate won't be re-processed by our listener
        try:
            # don't duplicate marker if already present
            if not any(h.lower().startswith(self.dup_marker.lower() + ":") for h in headers_copy):
                headers_copy.append("%s: 1" % self.dup_marker)
        except:
            pass
        return helpers.buildHttpMessage(headers_copy, body)
