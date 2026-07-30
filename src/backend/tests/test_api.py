import base64

from fastapi.testclient import TestClient

from main import app

client = TestClient(app)


def test_health_check():
    response = client.get("/")
    assert response.status_code == 200
    assert response.json() == {"service": "MiniVault", "status": "ok"}


def test_kv_write_read_delete(unlocked_vault, alice_token):
    # 1. Write
    write_res = client.post(
        "/kv/write",
        headers={"Authorization": f"Bearer {alice_token}"},
        json={"path": "secret/alice@example.com/db", "data": {"pass": "1234"}},
    )
    assert write_res.status_code == 201
    assert write_res.json()["status"] == "success"

    # 2. Read
    read_res = client.get(
        "/kv/read",
        headers={"Authorization": f"Bearer {alice_token}"},
        params={"path": "secret/alice@example.com/db"},
    )
    assert read_res.status_code == 200
    assert read_res.json()["data"] == {"pass": "1234"}

    # 3. Delete
    delete_res = client.delete(
        "/kv/delete",
        headers={"Authorization": f"Bearer {alice_token}"},
        params={"path": "secret/alice@example.com/db"},
    )
    assert delete_res.status_code == 200

    # 4. Read after delete
    read_res_2 = client.get(
        "/kv/read",
        headers={"Authorization": f"Bearer {alice_token}"},
        params={"path": "secret/alice@example.com/db"},
    )
    assert read_res_2.status_code == 404


def test_transit_encrypt_decrypt(unlocked_vault, alice_token):
    # 1. Create key
    create_res = client.post(
        "/transit/keys",
        headers={"Authorization": f"Bearer {alice_token}"},
        json={"key_name": "my-enc-key"},
    )
    assert create_res.status_code == 201

    # 2. Encrypt
    pt_b64 = base64.b64encode(b"hello vault").decode()
    enc_res = client.post(
        "/transit/encrypt",
        headers={"Authorization": f"Bearer {alice_token}"},
        json={"key_name": "my-enc-key", "plaintext_b64": pt_b64},
    )
    assert enc_res.status_code == 200
    ct = enc_res.json()["ciphertext"]
    assert ct.startswith("vault:my-enc-key:v1:")

    # 3. Decrypt
    dec_res = client.post(
        "/transit/decrypt",
        headers={"Authorization": f"Bearer {alice_token}"},
        json={"ciphertext": ct},
    )
    assert dec_res.status_code == 200
    assert dec_res.json()["plaintext_b64"] == pt_b64


def test_transit_sign_verify(unlocked_vault, alice_token):
    # 1. Create signing key
    create_res = client.post(
        "/transit/signing-keys",
        headers={"Authorization": f"Bearer {alice_token}"},
        json={"key_name": "my-sign-key", "signing_algorithm": "ED25519"},
    )
    assert create_res.status_code == 201

    # 2. Sign
    msg_b64 = base64.b64encode(b"hello signature").decode()
    sign_res = client.post(
        "/transit/sign",
        headers={"Authorization": f"Bearer {alice_token}"},
        json={"key_name": "my-sign-key", "message_b64": msg_b64, "message_type": "RAW"},
    )
    assert sign_res.status_code == 200
    sig_b64 = sign_res.json()["data"]["signature_b64"]

    # 3. Verify
    verify_res = client.post(
        "/transit/verify",
        headers={"Authorization": f"Bearer {alice_token}"},
        json={
            "key_name": "my-sign-key",
            "message_b64": msg_b64,
            "message_type": "RAW",
            "signature_b64": sig_b64,
        },
    )
    assert verify_res.status_code == 200
    assert verify_res.json()["data"]["signature_valid"] is True


def test_kv_versioning(unlocked_vault, alice_token):
    # 1. Write v1
    client.post(
        "/kv/write",
        headers={"Authorization": f"Bearer {alice_token}"},
        json={"path": "secret/alice@example.com/multi", "data": {"v": 1}},
    )
    # 2. Write v2
    client.post(
        "/kv/write",
        headers={"Authorization": f"Bearer {alice_token}"},
        json={"path": "secret/alice@example.com/multi", "data": {"v": 2}},
    )
    # 3. Write v3
    client.post(
        "/kv/write",
        headers={"Authorization": f"Bearer {alice_token}"},
        json={"path": "secret/alice@example.com/multi", "data": {"v": 3}},
    )

    # Read v1
    res = client.get(
        "/kv/version/1",
        headers={"Authorization": f"Bearer {alice_token}"},
        params={"path": "secret/alice@example.com/multi"},
    )
    assert res.status_code == 200
    assert res.json()["data"] == {"v": 1}

    # Read v2
    res = client.get(
        "/kv/version/2",
        headers={"Authorization": f"Bearer {alice_token}"},
        params={"path": "secret/alice@example.com/multi"},
    )
    assert res.status_code == 200
    assert res.json()["data"] == {"v": 2}

    # Read current (v3) via versioning API
    res = client.get(
        "/kv/version/3",
        headers={"Authorization": f"Bearer {alice_token}"},
        params={"path": "secret/alice@example.com/multi"},
    )
    assert res.status_code == 200
    assert res.json()["data"] == {"v": 3}


def test_transit_key_rotation(unlocked_vault, alice_token):
    # 1. Create key
    client.post(
        "/transit/keys",
        headers={"Authorization": f"Bearer {alice_token}"},
        json={"key_name": "rotate-me"},
    )

    # 2. Encrypt v1
    enc_v1 = client.post(
        "/transit/encrypt",
        headers={"Authorization": f"Bearer {alice_token}"},
        json={"key_name": "rotate-me", "plaintext_b64": base64.b64encode(b"v1 data").decode()},
    )
    ct_v1 = enc_v1.json()["ciphertext"]
    assert ct_v1.startswith("vault:rotate-me:v1:")

    # 3. Rotate key
    rot_res = client.post(
        "/transit/keys/rotate-me/rotate", headers={"Authorization": f"Bearer {alice_token}"}
    )
    assert rot_res.status_code == 200
    assert rot_res.json()["data"]["key_version"] == 2

    # 4. Encrypt v2
    enc_v2 = client.post(
        "/transit/encrypt",
        headers={"Authorization": f"Bearer {alice_token}"},
        json={"key_name": "rotate-me", "plaintext_b64": base64.b64encode(b"v2 data").decode()},
    )
    ct_v2 = enc_v2.json()["ciphertext"]
    assert ct_v2.startswith("vault:rotate-me:v2:")

    # 5. Decrypt v1 (should still work!)
    dec_v1 = client.post(
        "/transit/decrypt",
        headers={"Authorization": f"Bearer {alice_token}"},
        json={"ciphertext": ct_v1},
    )
    assert dec_v1.status_code == 200
    assert dec_v1.json()["plaintext_b64"] == base64.b64encode(b"v1 data").decode()

    # 6. Decrypt v2
    dec_v2 = client.post(
        "/transit/decrypt",
        headers={"Authorization": f"Bearer {alice_token}"},
        json={"ciphertext": ct_v2},
    )
    assert dec_v2.status_code == 200
    assert dec_v2.json()["plaintext_b64"] == base64.b64encode(b"v2 data").decode()


def test_acl_sharing(unlocked_vault, alice_token, bob_token):
    # Alice writes a KV secret
    res = client.post(
        "/kv/write",
        headers={"Authorization": f"Bearer {alice_token}"},
        json={"path": "secret/alice@example.com/shared", "data": {"secret": "squirrel"}},
    )
    assert res.status_code == 201

    # Bob tries to read, should fail
    res = client.get(
        "/kv/read",
        headers={"Authorization": f"Bearer {bob_token}"},
        params={"path": "secret/alice@example.com/shared"},
    )
    assert res.status_code == 403

    # Alice grants Bob read access
    res = client.post(
        "/acl/grant",
        headers={"Authorization": f"Bearer {alice_token}"},
        json={
            "resource_type": "kv",
            "resource_id": "secret/alice@example.com/shared",
            "grantee_email": "bob@example.com",
            "permissions": "READ",
        },
    )
    assert res.status_code == 200

    # Bob tries to read, should succeed
    res = client.get(
        "/kv/read",
        headers={"Authorization": f"Bearer {bob_token}"},
        params={"path": "secret/alice@example.com/shared"},
    )
    assert res.status_code == 200
    assert res.json()["data"] == {"secret": "squirrel"}


def test_audit_log(unlocked_vault, alice_token, bob_token):
    # 1. Create a key to trigger audit log
    res = client.post(
        "/transit/keys",
        headers={"Authorization": f"Bearer {alice_token}"},
        json={"key_name": "audit-test"},
    )
    assert res.status_code == 201, res.text

    # 2. Grant ACL to trigger audit log
    res = client.post(
        "/acl/grant",
        headers={"Authorization": f"Bearer {alice_token}"},
        json={
            "resource_type": "transit",
            "resource_id": "audit-test",
            "grantee_email": "bob@example.com",
            "permissions": "READ",
        },
    )
    assert res.status_code == 200, res.text

    from src.storage.db import get_db

    conn = get_db()

    logs = conn.execute("SELECT * FROM audit_log ORDER BY id ASC").fetchall()

    # There should be at least 2 logs now
    assert len(logs) >= 2

    # Check chaining of the last two
    last_log = logs[-1]
    prev_log = logs[-2]

    assert last_log["prev_hash"] == prev_log["row_hash"]
    assert last_log["action"] == "ACL_GRANT"
