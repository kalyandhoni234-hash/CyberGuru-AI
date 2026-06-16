import io


def test_analyze_file_rejects_oversized_upload(authenticated_client):
    oversized = b"x" * (5 * 1024 * 1024 + 1)

    response = authenticated_client.post(
        "/analyze-file",
        data={"file": (io.BytesIO(oversized), "sample.txt")},
        content_type="multipart/form-data",
        headers={"X-CSRF-Token": "csrf-test-token"},
    )

    body = response.get_data(as_text=True)
    assert response.status_code == 200
    assert "File too large" in body
    assert "5 MB" in body


def test_analyze_file_rejects_unsupported_extension(authenticated_client):
    response = authenticated_client.post(
        "/analyze-file",
        data={"file": (io.BytesIO(b"hello"), "sample.exe")},
        content_type="multipart/form-data",
        headers={"X-CSRF-Token": "csrf-test-token"},
    )

    assert response.status_code == 200
    assert "not supported" in response.get_data(as_text=True)

