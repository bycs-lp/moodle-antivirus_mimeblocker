<?php
// This file is part of Moodle - http://moodle.org/
//
// Moodle is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// Moodle is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with Moodle.  If not, see <http://www.gnu.org/licenses/>.

namespace antivirus_mimeblocker;

/**
 * Tests for mimeblocker antivirus scanner class.
 *
 * @package    antivirus_mimeblocker
 * @category   test
 * @copyright  2026 MBS
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */
final class scanner_test extends \advanced_testcase {

    /** @var string Temporary file used in testing. */
    protected $tempfile;

    protected function setUp(): void {
        parent::setUp();
        $this->resetAfterTest();

        // Create tempfile.
        $tempfolder = make_request_directory(false);
        $this->tempfile = $tempfolder . '/' . rand();
        touch($this->tempfile);
    }

    protected function tearDown(): void {
        @unlink($this->tempfile);
        parent::tearDown();
    }

    /**
     * Helper: create a scanner mock with detect_mimetype and get_config stubbed.
     *
     * We mock detect_mimetype() because finfo_file() is always available in the
     * test environment and will always return a real MIME type. Mocking lets us
     * simulate undetectable files (null) and control the exact MIME type without
     * needing real files of each type on disk.
     *
     * @param string|null $mimetype The MIME type that detect_mimetype should return.
     * @param string $scanmode 'allow' or 'deny'.
     * @param string $mimetypes Semicolon-separated configured MIME types.
     * @return scanner
     */
    private function create_scanner_mock(?string $mimetype, string $scanmode, string $mimetypes): scanner {
        $antivirus = $this->getMockBuilder('\antivirus_mimeblocker\scanner')
            ->onlyMethods(['detect_mimetype', 'get_config'])
            ->getMock();

        $antivirus->method('detect_mimetype')->willReturn($mimetype);
        $configmap = [
            ['scanmode', $scanmode],
            ['mimetypes', $mimetypes],
        ];
        $antivirus->method('get_config')->will($this->returnValueMap($configmap));

        // Reinitialise the configured mimetypes from the mocked config via reflection,
        // since the property is protected.
        $reflection = new \ReflectionProperty($antivirus, 'configuredmimetypes');
        $reflection->setValue($antivirus, explode(';', trim($mimetypes)));

        return $antivirus;
    }

    /**
     * When MIME detection returns null (no detection function available),
     * the scanner should return SCAN_RESULT_ERROR regardless of scan mode.
     *
     * This means the admin's "Action on scan failure" setting decides
     * whether the upload is ultimately accepted or rejected — not the plugin.
     */
    public function test_scan_file_undetectable_mimetype_returns_error(): void {
        // In allow mode, undetectable MIME → ERROR.
        $scanner = $this->create_scanner_mock(null, 'allow', 'text/plain;image/png');
        $result = $scanner->scan_file($this->tempfile, 'testfile.txt');
        $this->assertEquals(scanner::SCAN_RESULT_ERROR, $result);
        $this->assertDebuggingCalled();

        // In deny mode, undetectable MIME → ERROR (NOT silently passing).
        $scanner = $this->create_scanner_mock(null, 'deny', 'application/x-msdownload');
        $result = $scanner->scan_file($this->tempfile, 'testfile.exe');
        $this->assertEquals(scanner::SCAN_RESULT_ERROR, $result);
        $this->assertDebuggingCalled();
    }

    /**
     * Allow mode: a file with an allowed MIME type should pass.
     */
    public function test_scan_file_allow_mode_allowed_type(): void {
        $scanner = $this->create_scanner_mock('text/plain', 'allow', 'text/plain;image/png');
        $result = $scanner->scan_file($this->tempfile, 'readme.txt');
        $this->assertEquals(scanner::SCAN_RESULT_OK, $result);
    }

    /**
     * Allow mode: a file with a non-allowed MIME type should be blocked.
     */
    public function test_scan_file_allow_mode_blocked_type(): void {
        $scanner = $this->create_scanner_mock('application/x-msdownload', 'allow', 'text/plain;image/png');
        $result = $scanner->scan_file($this->tempfile, 'malware.exe');
        $this->assertEquals(scanner::SCAN_RESULT_FOUND, $result);
    }

    /**
     * Deny mode: a file with a denied MIME type should be blocked.
     */
    public function test_scan_file_deny_mode_blocked_type(): void {
        $scanner = $this->create_scanner_mock('application/x-msdownload', 'deny', 'application/x-msdownload');
        $result = $scanner->scan_file($this->tempfile, 'malware.exe');
        $this->assertEquals(scanner::SCAN_RESULT_FOUND, $result);
    }

    /**
     * Deny mode: a file with a non-denied MIME type should pass.
     */
    public function test_scan_file_deny_mode_allowed_type(): void {
        $scanner = $this->create_scanner_mock('text/plain', 'deny', 'application/x-msdownload');
        $result = $scanner->scan_file($this->tempfile, 'readme.txt');
        $this->assertEquals(scanner::SCAN_RESULT_OK, $result);
    }

    /**
     * Unreadable file should return SCAN_RESULT_FOUND.
     */
    public function test_scan_file_not_readable(): void {
        $scanner = $this->create_scanner_mock('text/plain', 'allow', 'text/plain');
        $nonexistent = $this->tempfile . '_nonexistent';

        $result = $scanner->scan_file($nonexistent, 'missing.txt');
        $this->assertEquals(scanner::SCAN_RESULT_FOUND, $result);
        $this->assertDebuggingCalled();
    }

    /**
     * Invalid scanmode config should return SCAN_RESULT_FOUND.
     */
    public function test_scan_file_invalid_scanmode(): void {
        $scanner = $this->create_scanner_mock('text/plain', 'invalid', 'text/plain');

        $result = $scanner->scan_file($this->tempfile, 'readme.txt');
        $this->assertEquals(scanner::SCAN_RESULT_FOUND, $result);
    }

    /**
     * When a blocked file is rejected, the temp file should still exist afterward
     * so the antivirus manager can quarantine it, and get_virus_found_message()
     * should return the structure the manager needs to display the error.
     */
    public function test_scan_file_blocked_does_not_delete_file(): void {
        $scanner = $this->create_scanner_mock('application/x-msdownload', 'allow', 'text/plain;image/png');
        $result = $scanner->scan_file($this->tempfile, 'malware.exe');

        // The manager expects SCAN_RESULT_FOUND to trigger quarantine + cleanup.
        $this->assertEquals(scanner::SCAN_RESULT_FOUND, $result);

        // The file must still exist so the manager can quarantine it before deleting.
        $this->assertFileExists($this->tempfile, 'Scanner should not delete the file — the antivirus manager handles cleanup');

        // The manager calls get_virus_found_message() to build the user-facing exception.
        $message = $scanner->get_virus_found_message();
        $this->assertArrayHasKey('string', $message);
        $this->assertArrayHasKey('component', $message);
        $this->assertArrayHasKey('placeholders', $message);
        $this->assertEquals('antivirus_mimeblocker', $message['component']);
        $this->assertEquals('virusfoundallow', $message['string']);
        $this->assertArrayHasKey('types', $message['placeholders']);
    }
}
