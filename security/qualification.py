"""Entry only through the verified root bundle for explicitly opted-in native tests."""
import json
import os


def main():
    if os.environ.get("LINXAI_TEST_KERNEL")!="1" or os.getuid()!=0 or os.geteuid()!=0:
        raise PermissionError("Explicit prepared root kernel lab opt-in required")
    from .policy_daemon import PolicyClient
    result=PolicyClient().call("qualify")
    print(json.dumps(result,sort_keys=True))
    if result.get("passed") is not True or result.get("origin")!="actual_kernel_probe":
        raise RuntimeError("Native kernel qualification was not demonstrated")
