#!/usr/bin/env python3
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from zcore.security import validate_release_gate, ReleaseGateError

TESTS_PASSED = 0
TESTS_FAILED = 0

def run_test(name, fn):
    global TESTS_PASSED, TESTS_FAILED
    try:
        fn()
        print(f"[PASS] {name}")
        TESTS_PASSED += 1
    except AssertionError as e:
        print(f"[FAIL] {name} - {e}")
        TESTS_FAILED += 1
    except Exception as e:
        print(f"[ERROR] {name} - {e}")
        TESTS_FAILED += 1

def test_gate1_default_secret():
    """GATE-1: secret par défaut refusé en release"""
    config = {"env": "release", "bind_host": "127.0.0.1", "local_only": True, "secret": "CHANGE_ME_LOCAL_DEV_ONLY", "azure": {"live": False}}
    try:
        validate_release_gate(config)
        raise AssertionError("Devrait lever ReleaseGateError")
    except ReleaseGateError:
        pass

def test_gate1_empty_secret():
    """GATE-1: secret vide refusé en release"""
    config = {"env": "release", "bind_host": "127.0.0.1", "local_only": True, "secret": "", "azure": {"live": False}}
    try:
        validate_release_gate(config)
        raise AssertionError("Devrait lever ReleaseGateError")
    except ReleaseGateError:
        pass

def test_gate2_bind_non_loopback():
    """GATE-2: bind hors loopback refusé si local_only=true"""
    config = {"env": "release", "bind_host": "0.0.0.0", "local_only": True, "secret": "valid_secret_32_chars_long____", "azure": {"live": False}}
    try:
        validate_release_gate(config)
        raise AssertionError("Devrait lever ReleaseGateError")
    except ReleaseGateError:
        pass

def test_gate3_not_local_only():
    """GATE-3: local_only=false refusé en release"""
    config = {"env": "release", "bind_host": "127.0.0.1", "local_only": False, "secret": "valid_secret_32_chars_long____", "azure": {"live": False}}
    try:
        validate_release_gate(config)
        raise AssertionError("Devrait lever ReleaseGateError")
    except ReleaseGateError:
        pass

def test_gate4_azure_live():
    """GATE-4: azure live refusé en release"""
    config = {"env": "release", "bind_host": "127.0.0.1", "local_only": True, "secret": "valid_secret_32_chars_long____", "azure": {"live": True}}
    try:
        validate_release_gate(config)
        raise AssertionError("Devrait lever ReleaseGateError")
    except ReleaseGateError:
        pass

def test_valid_config():
    """SANITY: config valide doit passer"""
    config = {"env": "release", "bind_host": "127.0.0.1", "local_only": True, "secret": "valid_secret_32_chars_long____", "azure": {"live": False}}
    validate_release_gate(config)

if __name__ == "__main__":
    print("=== Z-CORE V1 0.3.2-local Release Gate Tests ===\n")
    run_test("GATE-1 default secret", test_gate1_default_secret)
    run_test("GATE-1 empty secret", test_gate1_empty_secret)
    run_test("GATE-2 bind non loopback", test_gate2_bind_non_loopback)
    run_test("GATE-3 not local_only", test_gate3_not_local_only)
    run_test("GATE-4 azure live", test_gate4_azure_live)
    run_test("SANITY valid config", test_valid_config)
    
    print(f"\n=== RESULTAT: {TESTS_PASSED} passed, {TESTS_FAILED} failed ===")
    sys.exit(0 if TESTS_FAILED == 0 else 1)
