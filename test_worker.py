import hashlib
import unittest
from unittest import mock

import worker


class WorldCoreUpdateTests(unittest.TestCase):
    def test_normal_load_prefers_the_account_world_core_pointer(self):
        account_core = b"class WorldCore: pass\n"
        account_digest = hashlib.sha256(account_core).hexdigest()

        class Bucket:
            shared_prefix = "v4/all/"

            def kv_get(self, key):
                self.account_key = key
                return (account_digest, "account-etag")

            def get(self, _key):
                raise AssertionError("shared pointer must not be read when the account has one")

            def asset_get(self, digest):
                return account_core if digest == account_digest else None

        bucket = Bucket()
        marker = object()
        with mock.patch.object(worker, "load_module_from_source", return_value=marker) as load:
            result = worker.load_world_core_module(bucket)

        self.assertIs(result, marker)
        self.assertEqual(bucket.account_key, "circle.world_core")
        load.assert_called_once_with("directionally_world_core", account_core.decode("utf-8"))

    def test_normal_load_falls_back_to_the_shared_world_core_pointer(self):
        shared_core = b"class WorldCore: pass\n"
        shared_digest = hashlib.sha256(shared_core).hexdigest()

        class Bucket:
            shared_prefix = "v4/all/"

            def kv_get(self, key):
                self.account_key = key
                return (None, None)

            def get(self, key):
                self.shared_key = key
                return (shared_digest.encode(), "shared-etag")

            def asset_get(self, digest):
                return shared_core if digest == shared_digest else None

        bucket = Bucket()
        marker = object()
        with mock.patch.object(worker, "load_module_from_source", return_value=marker) as load:
            result = worker.load_world_core_module(bucket)

        self.assertIs(result, marker)
        self.assertEqual(bucket.account_key, "circle.world_core")
        self.assertEqual(bucket.shared_key, "v4/all/world_core")
        load.assert_called_once_with("directionally_world_core", shared_core.decode("utf-8"))

    def test_force_update_verifies_and_repoints_only_world_core(self):
        core = b"class WorldCore: pass\n"
        digest = hashlib.sha256(core).hexdigest()

        class Bucket:
            shared_prefix = "v4/all/"

            def get(self, key):
                self.shared_key = key
                return (digest.encode(), "shared-etag")

            def asset_get(self, candidate):
                return core if candidate == digest else None

        class Kv:
            def __init__(self):
                self.writes = []

            def kv_get(self, key):
                self.read_key = key
                return ("old-core", True)

            def kv_set(self, key, value, **conditions):
                self.writes.append((key, value, conditions))
                return (True, value)

        bucket = Bucket()
        kv = Kv()
        with mock.patch.object(worker, "build_bucket_and_kv", return_value=(bucket, kv)):
            result = worker.force_worldcore_update({}, [])

        self.assertEqual(bucket.shared_key, "v4/all/world_core")
        self.assertEqual(kv.read_key, "circle.world_core")
        self.assertEqual(
            kv.writes,
            [("circle.world_core", digest, {"if_match": "old-core", "if_absent": False})],
        )
        self.assertEqual(result, {"before": "old-core", "after": digest, "changed": True})

    def test_force_reset_repoints_world_and_reviewer_without_touching_other_state(self):
        core = b"class WorldCore: pass\n"
        world = b"from directionally_world_core import WorldCore\nclass World(WorldCore): pass\n"
        reviewer = b"reviewer bundle"
        core_hash = hashlib.sha256(core).hexdigest()
        world_hash = hashlib.sha256(world).hexdigest()
        reviewer_hash = hashlib.sha256(reviewer).hexdigest()

        class Bucket:
            shared_prefix = "v4/all/"

            def get(self, key):
                pointers = {
                    "v4/all/world_core": core_hash.encode(),
                    "v4/all/world_py": world_hash.encode(),
                    "v4/all/reviewer_bundle": reviewer_hash.encode(),
                }
                return (pointers[key], "etag")

            def asset_get(self, digest):
                return {core_hash: core, world_hash: world, reviewer_hash: reviewer}.get(digest)

        class Kv:
            def __init__(self):
                self.values = {"circle.world_core": "old-core", "circle.world_py": "old-world"}
                self.other_state = {"lab_notebook": ["keep me"]}
                self.writes = []

            def kv_get(self, key):
                return (self.values.get(key), key in self.values)

            def kv_set(self, key, value, if_match=None, if_absent=False):
                if if_absent and key in self.values:
                    return (False, self.values[key])
                if self.values.get(key) != if_match:
                    return (False, self.values.get(key))
                self.writes.append((key, value, if_match, if_absent))
                self.values[key] = value
                return (True, value)

        bucket, kv = Bucket(), Kv()
        with mock.patch.object(worker, "build_bucket_and_kv", return_value=(bucket, kv)):
            result = worker.force_world_reset({}, [])

        self.assertEqual(kv.values, {"circle.world_core": core_hash, "circle.world_py": world_hash, "reviewer_bundle": reviewer_hash})
        self.assertEqual(kv.other_state, {"lab_notebook": ["keep me"]})
        self.assertEqual(
            kv.writes,
            [
                ("circle.world_core", core_hash, "old-core", False),
                ("circle.world_py", world_hash, "old-world", False),
                ("reviewer_bundle", reviewer_hash, None, True),
            ],
        )
        self.assertTrue(result["changed"])
        self.assertEqual(result["world_core"], {"before": "old-core", "after": core_hash})
        self.assertEqual(result["world_py"], {"before": "old-world", "after": world_hash})
        self.assertEqual(result["reviewer_bundle"], {"before": None, "after": reviewer_hash})

    def test_force_reset_rolls_back_world_pointers_if_reviewer_loses_cas(self):
        core = b"core"
        world = b"world"
        reviewer = b"reviewer"
        core_hash = hashlib.sha256(core).hexdigest()
        world_hash = hashlib.sha256(world).hexdigest()
        reviewer_hash = hashlib.sha256(reviewer).hexdigest()

        class Bucket:
            shared_prefix = "v4/all/"

            def get(self, key):
                pointers = {"v4/all/world_core": core_hash, "v4/all/world_py": world_hash, "v4/all/reviewer_bundle": reviewer_hash}
                return (pointers[key].encode(), None)

            def asset_get(self, digest):
                return {core_hash: core, world_hash: world, reviewer_hash: reviewer}.get(digest)

        class Kv:
            def __init__(self):
                self.values = {"circle.world_core": "old-core", "circle.world_py": "old-world"}
                self.cas_count = 0

            def kv_get(self, key):
                return (self.values.get(key), key in self.values)

            def kv_set(self, key, value, if_match=None, if_absent=False):
                self.cas_count += 1
                if key == "reviewer_bundle" and value == reviewer_hash:
                    self.values[key] = "concurrent-reviewer"
                    return (False, self.values[key])
                if self.values[key] != if_match:
                    return (False, self.values[key])
                self.values[key] = value
                return (True, value)

        kv = Kv()
        with mock.patch.object(worker, "build_bucket_and_kv", return_value=(Bucket(), kv)):
            with self.assertRaisesRegex(RuntimeError, "reviewer_bundle changed concurrently"):
                worker.force_world_reset({}, [])
        self.assertEqual(kv.values["circle.world_core"], "old-core")
        self.assertEqual(kv.values["circle.world_py"], "old-world")
        self.assertEqual(kv.values["reviewer_bundle"], "concurrent-reviewer")

    def test_force_update_rejects_a_body_that_does_not_match_its_pointer(self):
        digest = hashlib.sha256(b"expected").hexdigest()

        class Bucket:
            shared_prefix = "v4/all/"

            def get(self, _key):
                return (digest.encode(), None)

            def asset_get(self, _candidate):
                return b"different"

        with mock.patch.object(worker, "build_bucket_and_kv", return_value=(Bucket(), object())):
            with self.assertRaisesRegex(RuntimeError, "failed its content hash"):
                worker.force_worldcore_update({}, [])


if __name__ == "__main__":
    unittest.main()
