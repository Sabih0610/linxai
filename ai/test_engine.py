# ai/test_engine.py
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ai.engine import AIEngine

TEST_CASES = [
    ("restart nginx",                           "service_restart"),
    ("start apache2",                           "service_start"),
    ("stop postgresql",                         "service_stop"),
    ("check status of ssh",                     "service_status"),
    ("enable nginx on boot",                    "service_enable"),
    ("disable bluetooth service",               "service_disable"),
    ("reload nginx config",                     "service_reload"),
    ("list all running processes",              "process_list"),
    ("kill process 4521",                       "process_kill"),
    ("show details of process 1234",            "process_info"),
    ("lower the priority of process 999",       "process_priority"),
    ("run backup.sh in the background",         "process_background"),
    ("check if port 80 is open",                "port_check"),
    ("list all open ports",                     "port_list"),
    ("allow port 443 through firewall",         "firewall_add"),
    ("block port 22 in firewall",               "firewall_remove"),
    ("show firewall rules",                     "firewall_list"),
    ("what is my ip address",                   "network_interfaces"),
    ("check network connectivity",              "network_status"),
    ("lookup dns for google.com",               "dns_lookup"),
    ("create a file called test.txt",           "file_create"),
    ("delete the file /tmp/old.log",            "file_delete"),
    ("move config.json to /etc/app/",           "file_move"),
    ("copy backup.tar to /mnt/storage/",        "file_copy"),
    ("change permissions of script.sh to 755",  "file_permissions"),
    ("read the contents of /etc/hosts",         "file_read"),
    ("find all log files in /var/log",          "file_find"),
    ("how much disk space is left",             "disk_usage"),
    ("show files in /home/ubuntu",              "directory_list"),
    ("create a new user called deploy",         "user_add"),
    ("delete user john",                        "user_remove"),
    ("list all users on the system",            "user_list"),
    ("change password for user alice",          "user_password"),
    ("what groups is user bob in",              "user_groups"),
    ("install htop",                            "package_install"),
    ("remove vim",                              "package_remove"),
    ("update all packages",                     "package_update"),
    ("list installed packages",                 "package_list"),
    ("search for nginx in apt",                 "package_search"),
    ("show cpu usage",                          "cpu_usage"),
    ("how much memory is being used",           "memory_usage"),
    ("how long has the system been running",    "system_uptime"),
    ("show system information",                 "system_info"),
    ("what kernel version is running",          "kernel_info"),
    ("show nginx logs",                         "log_view"),
    ("tail the syslog",                         "log_tail"),
    ("search for errors in /var/log/syslog",    "log_search"),
    ("restart nginx only if port 80 is free",   "service_restart"),
    ("what is taking up space on disk",         "disk_usage"),
    ("find which process is using port 8080",   "port_check"),
]


def run_accuracy_test():
    print("=" * 60)
    print("  LINxAI AI Engine — Accuracy Test")
    print(f"  Model: qwen2.5:1.5b | Test cases: {len(TEST_CASES)}")
    print("=" * 60)
    print()

    engine = AIEngine()
    passed = 0
    failed = []

    for i, (user_input, expected) in enumerate(TEST_CASES, 1):
        try:
            plan = engine.classify(user_input)
            got = plan.get("intent", "")
            ok = got == expected
            status = "✓" if ok else "✗"
            print(f"  [{status}] {i:3}. {user_input[:45]:<45} → {got}")
            if ok:
                passed += 1
            else:
                failed.append({"input": user_input, "expected": expected, "got": got})
        except Exception as e:
            print(f"  [E] {i:3}. {user_input[:45]:<45} → ERROR: {e}")
            failed.append({"input": user_input, "expected": expected, "got": "ERROR"})

    total = len(TEST_CASES)
    accuracy = (passed / total) * 100

    print()
    print("=" * 60)
    print(f"  RESULT: {passed}/{total} correct — {accuracy:.1f}% accuracy")
    print(f"  Target: 90.0% (45/50)")
    print(f"  Status: {'PASS ✓' if accuracy >= 90 else 'FAIL ✗ — improve system prompt'}")
    print("=" * 60)

    if failed:
        print(f"\n  Failed cases ({len(failed)}):")
        for f in failed:
            print(f"    input:    {f['input']}")
            print(f"    expected: {f['expected']}")
            print(f"    got:      {f['got']}")
            print()

    return accuracy >= 90


if __name__ == "__main__":
    success = run_accuracy_test()
    sys.exit(0 if success else 1)
