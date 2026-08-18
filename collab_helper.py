"""
Burp Suite Jython Extension - Collaborator Helper

Generates a Collaborator payload and exposes interactions via a local
HTTP API so standalone Python scripts can receive data
without needing a biid.

Installation:
    1. In Burp: Extender > Extensions > Add
    2. Extension type: Python
    3. Select this file
    4. The payload appears in the Collab Helper tab and Output

Local API endpoints:
    GET /collaborator  - returns the payload and server info
    GET /poll          - returns all accumulated DNS interactions
"""

from burp import IBurpExtender, ITab, IExtensionStateListener
from javax.swing import JPanel, JTextArea, JScrollPane
from java.awt import BorderLayout, Font
import threading
import json
import time

try:
    from BaseHTTPServer import HTTPServer, BaseHTTPRequestHandler
except ImportError:
    from http.server import HTTPServer, BaseHTTPRequestHandler

API_PORT = 18542
POLL_INTERVAL_MS = 1000


class BurpExtender(IBurpExtender, ITab, IExtensionStateListener):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Collaborator Helper")

        # Register unload listener so we can clean up the HTTP server
        callbacks.registerExtensionStateListener(self)

        # Create collaborator context
        self._collab = callbacks.createBurpCollaboratorClientContext()

        # Generate ONE payload - use it consistently
        self._payload_full = self._collab.generatePayload(True)
        parts = self._payload_full.split(".", 1)
        self._payload_bare = parts[0]
        self._server = parts[1] if len(parts) > 1 else ""

        # Accumulated interactions (thread-safe via lock)
        self._interactions = []
        self._lock = threading.Lock()

        # Server/thread references for cleanup
        self._http_server = None
        self._running = True

        # Build UI
        self._panel = JPanel(BorderLayout())
        text = JTextArea()
        text.setFont(Font("Monospaced", Font.PLAIN, 13))
        text.setEditable(False)

        info = []
        info.append("=" * 60)
        info.append("  Collaborator Helper")
        info.append("=" * 60)
        info.append("")
        info.append("  Payload:  %s" % self._payload_full)
        info.append("  Server:   %s" % self._server)
        info.append("")
        info.append("  Local API:  http://127.0.0.1:%d" % API_PORT)
        info.append("")
        info.append("-" * 60)
        info.append("  Usage:")
        info.append("")
        info.append("  python main.py --from-burp")
        info.append("")
        info.append("=" * 60)

        text.setText("\n".join(info))
        self._panel.add(JScrollPane(text), BorderLayout.CENTER)

        callbacks.addSuiteTab(self)

        for line in info:
            callbacks.printOutput(line)

        # Start background poller thread
        self._poll_thread = threading.Thread(target=self._poll_loop)
        self._poll_thread.daemon = True
        self._poll_thread.start()

        # Start local API server
        self._start_api()

    def extensionUnloaded(self):
        """Called by Burp when the extension is unloaded. Shuts down
        the HTTP server and polling thread so the port is freed."""
        self._callbacks.printOutput("Shutting down Collaborator Helper...")
        self._running = False
        if self._http_server:
            try:
                self._http_server.shutdown()
                self._http_server.server_close()
                self._callbacks.printOutput("HTTP server stopped.")
            except Exception as e:
                self._callbacks.printError("Error stopping HTTP server: %s" % str(e))

    def _poll_loop(self):
        """Background thread that continuously polls Burp's collaborator
        context and accumulates interactions."""
        while self._running:
            try:
                new_interactions = self._collab.fetchAllCollaboratorInteractions()
                if new_interactions:
                    with self._lock:
                        for interaction in new_interactions:
                            props = interaction.getProperties()
                            entry = {}
                            for key in props.keySet():
                                entry[str(key)] = str(props.get(key))
                            self._interactions.append(entry)
                    self._callbacks.printOutput(
                        "[+] Captured %d new interaction(s), total buffered: %d"
                        % (len(new_interactions), len(self._interactions))
                    )
            except Exception as e:
                if self._running:
                    self._callbacks.printError("Poll error: %s" % str(e))

            time.sleep(POLL_INTERVAL_MS / 1000.0)

    def _start_api(self):
        """Start a local HTTP server that exposes collaborator info."""
        ext = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                if self.path.startswith("/collaborator"):
                    resp = {
                        "payload": ext._payload_full,
                        "payload_bare": ext._payload_bare,
                        "server": ext._server,
                    }
                    body = json.dumps(resp).encode("utf-8")
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Access-Control-Allow-Origin", "*")
                    self.end_headers()
                    self.wfile.write(body)

                elif self.path.startswith("/poll"):
                    with ext._lock:
                        results = list(ext._interactions)
                        ext._interactions = []

                    body = json.dumps({"responses": results}).encode("utf-8")
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Access-Control-Allow-Origin", "*")
                    self.end_headers()
                    self.wfile.write(body)

                else:
                    self.send_response(404)
                    self.end_headers()

            def log_message(self, format, *args):
                pass

        def run():
            try:
                server = HTTPServer(("127.0.0.1", API_PORT), Handler)
                ext._http_server = server
                ext._callbacks.printOutput(
                    "Local API running on http://127.0.0.1:%d" % API_PORT
                )
                server.serve_forever()
            except Exception as e:
                ext._callbacks.printError(
                    "API server failed on port %d: %s -- "
                    "try restarting Burp if the port is stuck" % (API_PORT, str(e))
                )

        t = threading.Thread(target=run)
        t.daemon = True
        t.start()

    def getTabCaption(self):
        return "Collab Helper"

    def getUiComponent(self):
        return self._panel