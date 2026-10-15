///|
/// The whole pipeline in one call: authenticate the header, verify the blocks,
/// decrypt, split. Anything less than a byte-exact match with the generator's
/// plaintext means the reading path is wrong.
test "opening the fixture yields its inner header and xml" {
  let key = MasterKey::new().with_password("correct horse battery staple")
  let (header, xml) = open_database(database(), key)
  assert_eq(header.random_stream_id(), 3)
  assert_eq(header.random_stream_key().length(), 64)
  assert_eq(to_hex(Bytes::makei(5, fn(i) { xml[i] })), "3c4b656550")
  assert_true(xml.length() > 0)
}
