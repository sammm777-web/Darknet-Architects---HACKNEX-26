"""
Unit test for data loader validation and scenario switching.
"""
import io
from data.demo_scenarios import DEMO_SCENARIOS, get_demo_scenario
from utils.data_loader import load_dataset

class DummyUploadedFile:
    def __init__(self, name, content_bytes):
        self.name = name
        self.size = len(content_bytes)
        self._content = content_bytes
    
    def getvalue(self):
        return self._content

def run_tests():
    # 1. Test Demo Scenarios
    print("Testing Demo Scenarios...")
    assert len(DEMO_SCENARIOS) == 3
    assert "clean_logs" in DEMO_SCENARIOS
    assert "usb_exfiltration" in DEMO_SCENARIOS
    assert "lateral_movement" in DEMO_SCENARIOS
    
    for s_id, s_data in DEMO_SCENARIOS.items():
        assert "name" in s_data
        assert "metrics" in s_data
        assert "nodes" in s_data
        assert "edges" in s_data
        print(f"  [OK] {s_id}: {s_data['name']} (Threat: {s_data['metrics']['threat_level']}, Total Logs: {s_data['metrics']['total_logs']})")

    # 2. Test Data Loader with Valid CSV
    print("\nTesting Data Loader with Valid CSV...")
    csv_bytes = b"timestamp,src_ip,dest_ip,action\n2026-10-07 10:00:01,10.0.0.1,10.0.0.2,ALLOW\n2026-10-07 10:00:02,10.0.0.1,10.0.0.3,DENY\n"
    f_csv = DummyUploadedFile("firewall_events.csv", csv_bytes)
    res_csv = load_dataset(f_csv)
    assert res_csv["status"] == "success"
    assert res_csv["total_logs"] == 2
    assert res_csv["file_type"] == "CSV"
    print(f"  [OK] CSV Loaded: {res_csv['file_name']}, Logs: {res_csv['total_logs']}, Size: {res_csv['file_size']}")

    # 3. Test Data Loader with Valid JSON
    print("\nTesting Data Loader with Valid JSON...")
    json_bytes = b'[{"event_id": 101, "msg": "auth_success"}, {"event_id": 102, "msg": "auth_fail"}]'
    f_json = DummyUploadedFile("auth_logs.json", json_bytes)
    res_json = load_dataset(f_json)
    assert res_json["status"] == "success"
    assert res_json["total_logs"] == 2
    assert res_json["file_type"] == "JSON"
    print(f"  [OK] JSON Loaded: {res_json['file_name']}, Logs: {res_json['total_logs']}")

    # 4. Test Data Loader with Valid LOG/TXT
    print("\nTesting Data Loader with Valid LOG...")
    log_bytes = b"Oct  7 10:00:01 host-01 sshd[123]: Accepted publickey\nOct  7 10:00:02 host-01 sshd[124]: Disconnected\n"
    f_log = DummyUploadedFile("syslog.log", log_bytes)
    res_log = load_dataset(f_log)
    assert res_log["status"] == "success"
    assert res_log["total_logs"] == 2
    assert res_log["file_type"] == "LOG"
    print(f"  [OK] LOG Loaded: {res_log['file_name']}, Logs: {res_log['total_logs']}")

    # 5. Test Data Loader Error Cases
    print("\nTesting Error Cases...")
    # Empty file
    f_empty = DummyUploadedFile("empty.csv", b"")
    res_empty = load_dataset(f_empty)
    assert res_empty["status"] == "error"
    print(f"  [OK] Empty file handled gracefully: {res_empty['error_message']}")

    # Unsupported format
    f_exe = DummyUploadedFile("payload.exe", b"MZ\x90\x00")
    res_exe = load_dataset(f_exe)
    assert res_exe["status"] == "error"
    print(f"  [OK] Unsupported format handled gracefully: {res_exe['error_message']}")

    # Corrupt JSON
    f_bad_json = DummyUploadedFile("corrupt.json", b"{broken json")
    res_bad_json = load_dataset(f_bad_json)
    assert res_bad_json["status"] == "error"
    print(f"  [OK] Corrupt JSON handled gracefully: {res_bad_json['error_message']}")

    # None file
    res_none = load_dataset(None)
    assert res_none["status"] == "empty"
    print(f"  [OK] None file handled gracefully: {res_none['message']}")

    print("\nALL DATA TESTS PASSED SUCCESSFULLY!")

if __name__ == "__main__":
    run_tests()
