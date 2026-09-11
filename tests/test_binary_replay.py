def test_recorded_binary_and_empty_files_survive_reopening(manager):
    """Gradle wrapper JARs must not break post-hoc scoring of Android sessions."""
    session = manager.create()
    session.begin_run("seed")
    files = {"gradle/wrapper/gradle-wrapper.jar": b"PK\x03\x04\xff\x00", "empty.bin": b"", "README": "sample"}
    session.write_files(files)
    session.end_run()
    session_id = session.info.session_id
    manager.close(session_id)
    recorded = manager.open_recorded(session_id)
    assert recorded.sandbox.read_files(list(files)) == files
