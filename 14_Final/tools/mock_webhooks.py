from flask import Flask, request, jsonify

app = Flask(__name__)

@app.post('/edr/isolate')
def edr_isolate():
    data = request.get_json(force=True)
    return jsonify({"ok": True, "action": "edr.isolate", "received": data})

@app.post('/edr/unisolate')
def edr_unisolate():
    data = request.get_json(force=True)
    return jsonify({"ok": True, "action": "edr.unisolate", "received": data})

@app.post('/edr/scan')
def edr_scan():
    data = request.get_json(force=True)
    return jsonify({"ok": True, "action": "edr.scan", "received": data})

@app.post('/backup/trigger')
def backup_trigger():
    data = request.get_json(force=True)
    return jsonify({"ok": True, "action": "backup.trigger", "received": data})

@app.post('/backup/restore')
def backup_restore():
    data = request.get_json(force=True)
    return jsonify({"ok": True, "action": "backup.restore", "received": data})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5055)
