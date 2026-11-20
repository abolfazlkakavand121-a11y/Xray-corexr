import unittest
from tls_mutation_lab import ClientHelloError, _encode_hello, _extract_client_hello, _hello_parts, _record, classify_response, generate_candidates

class ClientHelloMutationTests(unittest.TestCase):
    def make_hello(self):
        prefix = b"\x03\x03" + bytes(range(32)) + b"\x00" + b"\x00\x02\x13\x01" + b"\x01\x00"
        name = b"example.test"
        sni_list = b"\x00" + (len(name) + 3).to_bytes(2, "big") + b"\x00" + len(name).to_bytes(2, "big") + name
        extensions = [(0, len(sni_list).to_bytes(2, "big") + sni_list), (43, b"\x02\x03\x04")]
        return _record(22, b"\x03\x01", _encode_hello(prefix, extensions))

    def test_extract_and_parse(self):
        version, hello = _extract_client_hello(self.make_hello())
        self.assertEqual(version, b"\x03\x01")
        prefix, extensions = _hello_parts(hello)
        self.assertEqual([e[0] for e in extensions], [0, 43])
        self.assertTrue(prefix)

    def test_record_split_preserves_handshake(self):
        candidates = generate_candidates(self.make_hello())
        expected = _extract_client_hello(self.make_hello())[1]
        for candidate in candidates:
            if candidate.name.startswith("record-split-"):
                chunks, offset = [], 0
                while offset < len(candidate.wire):
                    self.assertEqual(candidate.wire[offset], 22)
                    size = int.from_bytes(candidate.wire[offset + 3:offset + 5], "big")
                    chunks.append(candidate.wire[offset + 5:offset + 5 + size])
                    offset += 5 + size
                self.assertEqual(b"".join(chunks), expected)

    def test_extension_mutations_reparse(self):
        for candidate in generate_candidates(self.make_hello()):
            if candidate.name in {"extensions-reversed", "sni-first", "sni-last", "padding-32", "padding-128"}:
                _, hello = _extract_client_hello(candidate.wire)
                _, extensions = _hello_parts(hello)
                self.assertTrue(extensions)

    def test_reject_truncated_record(self):
        with self.assertRaises(ClientHelloError):
            _extract_client_hello(b"\x16\x03\x01\x00\x20\x01")

    def test_response_classification(self):
        self.assertEqual(classify_response(b"\x15\x03\x03\x00\x02\x02\x28"), "tls-alert")
        self.assertEqual(classify_response(b"\x16\x03\x03\x00\x04"), "tls-handshake")
        self.assertEqual(classify_response(b""), "empty")

if __name__ == "__main__":
    unittest.main()
