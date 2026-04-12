"""
Comprehensive tests for rapidscan.py

These tests cover the utility functions, data structure integrity,
argument parsing, and class behavior of the rapidscan scanner.
"""
import sys
import subprocess
from io import StringIO
from unittest import mock

import pytest


# ---------------------------------------------------------------------------
# Tests for display_time()
# ---------------------------------------------------------------------------
class TestDisplayTime:
    """Tests for the time formatting utility function."""

    def test_zero_seconds(self, rapidscan_module):
        # 0 seconds + 1 = 1s
        result = rapidscan_module.display_time(0)
        assert result == "1s"

    def test_one_second(self, rapidscan_module):
        # 1 + 1 = 2s
        result = rapidscan_module.display_time(1)
        assert result == "2s"

    def test_sixty_seconds(self, rapidscan_module):
        # 60 + 1 = 61 => 1m 1s
        result = rapidscan_module.display_time(60)
        assert result == "1m 1s"

    def test_exact_minute(self, rapidscan_module):
        # 59 + 1 = 60 => 1m
        result = rapidscan_module.display_time(59)
        assert result == "1m"

    def test_hours_minutes_seconds(self, rapidscan_module):
        # 3661 + 1 = 3662 => 1h 1m 2s
        result = rapidscan_module.display_time(3661)
        assert result == "1h 1m 2s"

    def test_exact_hour(self, rapidscan_module):
        # 3599 + 1 = 3600 => 1h
        result = rapidscan_module.display_time(3599)
        assert result == "1h"

    def test_multiple_hours(self, rapidscan_module):
        # 7200 + 1 = 7201 => 2h 0m 1s
        result = rapidscan_module.display_time(7200)
        assert result == "2h 1s"

    def test_granularity_one(self, rapidscan_module):
        # 3661 + 1 = 3662 => only first unit: "1h"
        result = rapidscan_module.display_time(3661, granularity=1)
        assert result == "1h"

    def test_granularity_two(self, rapidscan_module):
        # 3661 + 1 = 3662 => first two units: "1h 1m"
        result = rapidscan_module.display_time(3661, granularity=2)
        assert result == "1h 1m"

    def test_large_value(self, rapidscan_module):
        # 86400 + 1 = 86401 => 24h 0m 1s
        result = rapidscan_module.display_time(86400)
        assert result == "24h 1s"


# ---------------------------------------------------------------------------
# Tests for url_maker()
# ---------------------------------------------------------------------------
class TestUrlMaker:
    """Tests for URL normalization and host extraction."""

    def test_plain_domain(self, rapidscan_module):
        assert rapidscan_module.url_maker("example.com") == "example.com"

    def test_http_prefix(self, rapidscan_module):
        assert rapidscan_module.url_maker("http://example.com") == "example.com"

    def test_https_prefix(self, rapidscan_module):
        assert rapidscan_module.url_maker("https://example.com") == "example.com"

    def test_www_prefix_stripped(self, rapidscan_module):
        assert rapidscan_module.url_maker("http://www.example.com") == "example.com"

    def test_www_without_scheme(self, rapidscan_module):
        assert rapidscan_module.url_maker("www.example.com") == "example.com"

    def test_subdomain_preserved(self, rapidscan_module):
        assert rapidscan_module.url_maker("http://sub.example.com") == "sub.example.com"

    def test_path_stripped(self, rapidscan_module):
        assert rapidscan_module.url_maker("http://example.com/path/page") == "example.com"

    def test_port_preserved(self, rapidscan_module):
        assert rapidscan_module.url_maker("http://example.com:8080") == "example.com:8080"

    def test_https_www_with_path(self, rapidscan_module):
        assert rapidscan_module.url_maker("https://www.example.com/test") == "example.com"

    def test_ip_address(self, rapidscan_module):
        assert rapidscan_module.url_maker("http://192.168.1.1") == "192.168.1.1"

    def test_ip_address_without_scheme(self, rapidscan_module):
        assert rapidscan_module.url_maker("192.168.1.1") == "192.168.1.1"


# ---------------------------------------------------------------------------
# Tests for vul_info()
# ---------------------------------------------------------------------------
class TestVulInfo:
    """Tests for vulnerability severity classification formatting."""

    def test_critical(self, rapidscan_module):
        result = rapidscan_module.vul_info("c")
        assert "critical" in result
        assert rapidscan_module.bcolors.BG_CRIT_TXT in result

    def test_high(self, rapidscan_module):
        result = rapidscan_module.vul_info("h")
        assert "high" in result
        assert rapidscan_module.bcolors.BG_HIGH_TXT in result

    def test_medium(self, rapidscan_module):
        result = rapidscan_module.vul_info("m")
        assert "medium" in result
        assert rapidscan_module.bcolors.BG_MED_TXT in result

    def test_low(self, rapidscan_module):
        result = rapidscan_module.vul_info("l")
        assert "low" in result
        assert rapidscan_module.bcolors.BG_LOW_TXT in result

    def test_info_default(self, rapidscan_module):
        result = rapidscan_module.vul_info("i")
        assert "info" in result
        assert rapidscan_module.bcolors.BG_INFO_TXT in result

    def test_unknown_defaults_to_info(self, rapidscan_module):
        result = rapidscan_module.vul_info("x")
        assert "info" in result

    def test_empty_string_defaults_to_info(self, rapidscan_module):
        result = rapidscan_module.vul_info("")
        assert "info" in result

    def test_all_contain_endc(self, rapidscan_module):
        """All severity results should end with ENDC color reset."""
        for val in ["c", "h", "m", "l", "i"]:
            result = rapidscan_module.vul_info(val)
            assert rapidscan_module.bcolors.ENDC in result


# ---------------------------------------------------------------------------
# Tests for bcolors class
# ---------------------------------------------------------------------------
class TestBcolors:
    """Verify that the bcolors class has the expected ANSI escape sequences."""

    def test_header_is_string(self, rapidscan_module):
        assert isinstance(rapidscan_module.bcolors.HEADER, str)

    def test_escape_sequences_start_with_esc(self, rapidscan_module):
        bc = rapidscan_module.bcolors
        for attr in [
            "HEADER", "OKBLUE", "OKGREEN", "WARNING", "BADFAIL",
            "ENDC", "BOLD", "UNDERLINE",
            "BG_ERR_TXT", "BG_HEAD_TXT", "BG_ENDL_TXT",
            "BG_CRIT_TXT", "BG_HIGH_TXT", "BG_MED_TXT",
            "BG_LOW_TXT", "BG_INFO_TXT",
        ]:
            val = getattr(bc, attr)
            assert val.startswith("\033["), f"{attr} does not start with ESC["

    def test_endc_resets(self, rapidscan_module):
        assert rapidscan_module.bcolors.ENDC == "\033[0m"


# ---------------------------------------------------------------------------
# Tests for terminal_size()
# ---------------------------------------------------------------------------
class TestTerminalSize:
    """Tests for the terminal column width detection."""

    def test_returns_int(self, rapidscan_module):
        result = rapidscan_module.terminal_size()
        assert isinstance(result, int)

    def test_fallback_on_error(self, rapidscan_module):
        with mock.patch("subprocess.check_output", side_effect=subprocess.CalledProcessError(1, "stty")):
            result = rapidscan_module.terminal_size()
            assert result == 20

    def test_parses_stty_output(self, rapidscan_module):
        with mock.patch("subprocess.check_output", return_value=b"24 80"):
            result = rapidscan_module.terminal_size()
            assert result == 80

    def test_large_terminal(self, rapidscan_module):
        with mock.patch("subprocess.check_output", return_value=b"50 200"):
            result = rapidscan_module.terminal_size()
            assert result == 200


# ---------------------------------------------------------------------------
# Tests for check_internet()
# ---------------------------------------------------------------------------
class TestCheckInternet:
    """Tests for internet connectivity checking."""

    def test_returns_1_when_connected(self, rapidscan_module):
        with mock.patch("os.system") as mock_system:
            # Simulate successful ping by writing expected content to rs_net
            def fake_system(cmd):
                if "ping" in cmd:
                    with open("rs_net", "w") as f:
                        f.write("1 packets transmitted, 1 received, 0% packet loss")
                return 0

            mock_system.side_effect = fake_system
            result = rapidscan_module.check_internet()
            assert result == 1

    def test_returns_0_when_disconnected(self, rapidscan_module):
        with mock.patch("os.system") as mock_system:
            def fake_system(cmd):
                if "ping" in cmd:
                    with open("rs_net", "w") as f:
                        # Use text that does NOT contain "0% packet loss" as substring
                        f.write("1 packets transmitted, 0 received, time 0ms")
                return 0

            mock_system.side_effect = fake_system
            result = rapidscan_module.check_internet()
            assert result == 0


# ---------------------------------------------------------------------------
# Tests for get_parser()
# ---------------------------------------------------------------------------
class TestGetParser:
    """Tests for argument parser configuration."""

    def test_parser_with_target(self, rapidscan_module):
        parser = rapidscan_module.get_parser()
        args = parser.parse_args(["example.com"])
        assert args.target == "example.com"
        assert args.help is False
        assert args.update is False
        assert args.skip == []
        assert args.nospinner is False

    def test_parser_with_help_flag(self, rapidscan_module):
        parser = rapidscan_module.get_parser()
        args = parser.parse_args(["--help"])
        assert args.help is True

    def test_parser_with_update_flag(self, rapidscan_module):
        parser = rapidscan_module.get_parser()
        args = parser.parse_args(["--update"])
        assert args.update is True

    def test_parser_with_nospinner(self, rapidscan_module):
        parser = rapidscan_module.get_parser()
        args = parser.parse_args(["--nospinner", "example.com"])
        assert args.nospinner is True
        assert args.target == "example.com"

    def test_parser_with_skip(self, rapidscan_module):
        parser = rapidscan_module.get_parser()
        args = parser.parse_args(["--skip", "nmap", "--skip", "nikto", "example.com"])
        assert "nmap" in args.skip
        assert "nikto" in args.skip
        assert len(args.skip) == 2

    def test_parser_no_args_gives_empty_target(self, rapidscan_module):
        parser = rapidscan_module.get_parser()
        args = parser.parse_args([])
        assert args.target == ""

    def test_parser_short_flags(self, rapidscan_module):
        parser = rapidscan_module.get_parser()
        args = parser.parse_args(["-n", "-u"])
        assert args.nospinner is True
        assert args.update is True

    def test_parser_skip_with_short_flag(self, rapidscan_module):
        parser = rapidscan_module.get_parser()
        args = parser.parse_args(["-s", "nmap", "example.com"])
        assert "nmap" in args.skip

    def test_parser_invalid_skip_raises(self, rapidscan_module):
        parser = rapidscan_module.get_parser()
        with pytest.raises(SystemExit):
            parser.parse_args(["--skip", "invalidtool", "example.com"])

    def test_parser_multiple_skip_same_tool(self, rapidscan_module):
        parser = rapidscan_module.get_parser()
        args = parser.parse_args(["--skip", "nmap", "--skip", "nmap", "example.com"])
        assert args.skip == ["nmap", "nmap"]


# ---------------------------------------------------------------------------
# Tests for data structure integrity
# ---------------------------------------------------------------------------
class TestDataStructureIntegrity:
    """Verify that the parallel data structures are consistent."""

    def test_tool_names_cmd_resp_status_same_length(self, rapidscan_module):
        """All four tool arrays must have the same number of entries."""
        assert len(rapidscan_module.tool_names) == len(rapidscan_module.tool_cmd)
        assert len(rapidscan_module.tool_cmd) == len(rapidscan_module.tool_resp)
        assert len(rapidscan_module.tool_resp) == len(rapidscan_module.tool_status)

    def test_tool_checks_matches(self, rapidscan_module):
        """tool_checks should equal the common length of the arrays."""
        expected = len(rapidscan_module.tool_names)
        assert rapidscan_module.tool_checks == expected

    def test_tool_names_have_four_elements(self, rapidscan_module):
        for i, entry in enumerate(rapidscan_module.tool_names):
            assert len(entry) == 4, f"tool_names[{i}] has {len(entry)} elements, expected 4"

    def test_tool_cmd_have_two_elements(self, rapidscan_module):
        for i, entry in enumerate(rapidscan_module.tool_cmd):
            assert len(entry) == 2, f"tool_cmd[{i}] has {len(entry)} elements, expected 2"

    def test_tool_resp_have_three_elements(self, rapidscan_module):
        for i, entry in enumerate(rapidscan_module.tool_resp):
            assert len(entry) == 3, f"tool_resp[{i}] has {len(entry)} elements, expected 3"

    def test_tool_status_have_six_elements(self, rapidscan_module):
        for i, entry in enumerate(rapidscan_module.tool_status):
            assert len(entry) == 6, f"tool_status[{i}] has {len(entry)} elements, expected 6"

    def test_tool_resp_severity_values(self, rapidscan_module):
        """All severity values should be one of c, h, m, l, i."""
        valid_severities = {"c", "h", "m", "l", "i"}
        for i, entry in enumerate(rapidscan_module.tool_resp):
            assert entry[1] in valid_severities, \
                f"tool_resp[{i}] has invalid severity '{entry[1]}'"

    def test_tool_resp_fix_references_valid(self, rapidscan_module):
        """Each tool_resp fix reference must be a valid index into tools_fix."""
        max_fix = len(rapidscan_module.tools_fix)
        for i, entry in enumerate(rapidscan_module.tool_resp):
            fix_ref = entry[2]
            assert 1 <= fix_ref <= max_fix, \
                f"tool_resp[{i}] references fix {fix_ref}, but tools_fix has {max_fix} entries"

    def test_tools_fix_entries_have_three_elements(self, rapidscan_module):
        for i, entry in enumerate(rapidscan_module.tools_fix):
            assert len(entry) == 3, f"tools_fix[{i}] has {len(entry)} elements, expected 3"

    def test_tools_fix_sequential_ids(self, rapidscan_module):
        """tools_fix IDs should be sequential starting from 1."""
        for i, entry in enumerate(rapidscan_module.tools_fix):
            assert entry[0] == i + 1, \
                f"tools_fix[{i}] has ID {entry[0]}, expected {i + 1}"

    def test_tools_precheck_not_empty(self, rapidscan_module):
        assert len(rapidscan_module.tools_precheck) > 0

    def test_tools_precheck_entries_are_lists(self, rapidscan_module):
        for i, entry in enumerate(rapidscan_module.tools_precheck):
            assert isinstance(entry, list), f"tools_precheck[{i}] is not a list"
            assert len(entry) == 1, f"tools_precheck[{i}] should have 1 element"
            assert isinstance(entry[0], str), f"tools_precheck[{i}][0] is not a string"

    def test_tool_names_identifiers_unique(self, rapidscan_module):
        """Tool name identifiers (first element) should be unique."""
        ids = [entry[0] for entry in rapidscan_module.tool_names]
        assert len(ids) == len(set(ids)), "Duplicate tool name identifiers found"

    def test_total_tools_count(self, rapidscan_module):
        """There should be 80 tools configured (tool #11 fierce is commented out)."""
        assert len(rapidscan_module.tool_names) == 80


# ---------------------------------------------------------------------------
# Tests for Spinner class
# ---------------------------------------------------------------------------
class TestSpinner:
    """Tests for the idle loader/spinner class."""

    def test_spinner_init_default(self, rapidscan_module):
        s = rapidscan_module.Spinner()
        assert s.busy is False
        assert s.delay == 0.005
        assert s.disabled is False

    def test_spinner_init_custom_delay(self, rapidscan_module):
        s = rapidscan_module.Spinner(delay=0.1)
        assert s.delay == 0.1

    def test_spinner_start_stop(self, rapidscan_module):
        s = rapidscan_module.Spinner()
        s.disabled = True  # disable visual output
        s.start()
        assert s.busy is True
        s.stop()
        assert s.busy is False

    def test_spinning_cursor_yields_space(self, rapidscan_module):
        s = rapidscan_module.Spinner()
        gen = s.spinning_cursor()
        first = next(gen)
        assert first == " "

    def test_spinner_disabled_flag(self, rapidscan_module):
        s = rapidscan_module.Spinner()
        s.disabled = True
        s.start()
        import time
        time.sleep(0.05)
        s.stop()
        # Should complete without errors


# ---------------------------------------------------------------------------
# Tests for vul_remed_info()
# ---------------------------------------------------------------------------
class TestVulRemedInfo:
    """Tests for the vulnerability remediation information display."""

    def test_prints_threat_level(self, rapidscan_module, capsys):
        # We need to call with valid indices that reference tool_resp and tools_fix
        # Since tool arrays are shuffled, find a valid index
        idx = 0
        severity = rapidscan_module.tool_resp[idx][1]
        fix_ref = rapidscan_module.tool_resp[idx][2]

        rapidscan_module.vul_remed_info(idx, severity, fix_ref)
        captured = capsys.readouterr()

        assert "Vulnerability Threat Level" in captured.out
        assert "Vulnerability Definition" in captured.out
        assert "Vulnerability Remediation" in captured.out


# ---------------------------------------------------------------------------
# Tests for helper() and logo()
# ---------------------------------------------------------------------------
class TestHelperAndLogo:
    """Tests for display functions."""

    def test_helper_prints_usage(self, rapidscan_module, capsys):
        rapidscan_module.helper()
        captured = capsys.readouterr()
        assert "rapidscan.py" in captured.out
        assert "Information:" in captured.out
        assert "Legends:" in captured.out
        assert "Vulnerability Information:" in captured.out

    def test_logo_prints_ascii_art(self, rapidscan_module, capsys):
        rapidscan_module.logo()
        captured = capsys.readouterr()
        assert "Multi-Tool Web Vulnerability Scanner" in captured.out

    def test_helper_mentions_skip(self, rapidscan_module, capsys):
        rapidscan_module.helper()
        captured = capsys.readouterr()
        assert "--skip" in captured.out

    def test_helper_mentions_update(self, rapidscan_module, capsys):
        rapidscan_module.helper()
        captured = capsys.readouterr()
        assert "--update" in captured.out

    def test_helper_mentions_nospinner(self, rapidscan_module, capsys):
        rapidscan_module.helper()
        captured = capsys.readouterr()
        assert "--nospinner" in captured.out


# ---------------------------------------------------------------------------
# Tests for clear()
# ---------------------------------------------------------------------------
class TestClear:
    """Tests for the line-clearing function."""

    def test_clear_writes_escape_sequences(self, rapidscan_module):
        with mock.patch("sys.stdout") as mock_stdout:
            rapidscan_module.clear()
            assert mock_stdout.write.call_count == 2
            calls = [c[0][0] for c in mock_stdout.write.call_args_list]
            assert "\033[F" in calls
            assert "\033[K" in calls


# ---------------------------------------------------------------------------
# Tests for module-level constants
# ---------------------------------------------------------------------------
class TestModuleConstants:
    """Tests for module-level constant values."""

    def test_cursor_up_one(self, rapidscan_module):
        assert rapidscan_module.CURSOR_UP_ONE == "\x1b[1A"

    def test_erase_line(self, rapidscan_module):
        assert rapidscan_module.ERASE_LINE == "\x1b[2K"

    def test_intervals_tuple(self, rapidscan_module):
        intervals = rapidscan_module.intervals
        assert len(intervals) == 3
        names = [i[0] for i in intervals]
        assert "h" in names
        assert "m" in names
        assert "s" in names

    def test_intervals_descending_values(self, rapidscan_module):
        """Intervals should be in descending order of count."""
        intervals = rapidscan_module.intervals
        values = [i[1] for i in intervals]
        assert values == sorted(values, reverse=True)

    def test_proc_indicators_are_strings(self, rapidscan_module):
        assert isinstance(rapidscan_module.proc_high, str)
        assert isinstance(rapidscan_module.proc_med, str)
        assert isinstance(rapidscan_module.proc_low, str)

    def test_proc_indicators_contain_bullet(self, rapidscan_module):
        assert "●" in rapidscan_module.proc_high
        assert "●" in rapidscan_module.proc_med
        assert "●" in rapidscan_module.proc_low


# ---------------------------------------------------------------------------
# Tests for edge cases in display_time
# ---------------------------------------------------------------------------
class TestDisplayTimeEdgeCases:
    """Additional edge case tests for display_time."""

    def test_negative_seconds(self, rapidscan_module):
        """Negative input: -1 + 1 = 0, no components => empty string."""
        result = rapidscan_module.display_time(-1)
        assert result == ""

    def test_very_large_seconds(self, rapidscan_module):
        # 100000 + 1 = 100001 => 27h 46m 41s
        result = rapidscan_module.display_time(100000)
        assert "h" in result
        assert "m" in result
        assert "s" in result

    def test_just_under_minute(self, rapidscan_module):
        # 58 + 1 = 59 => 59s
        result = rapidscan_module.display_time(58)
        assert result == "59s"

    def test_two_minutes(self, rapidscan_module):
        # 119 + 1 = 120 => 2m
        result = rapidscan_module.display_time(119)
        assert result == "2m"


# ---------------------------------------------------------------------------
# Tests for url_maker edge cases
# ---------------------------------------------------------------------------
class TestUrlMakerEdgeCases:
    """Additional edge case tests for url_maker."""

    def test_empty_string(self, rapidscan_module):
        # Empty URL, the http:// prefix will be added, parsed netloc = empty
        result = rapidscan_module.url_maker("")
        assert isinstance(result, str)

    def test_url_with_query_string(self, rapidscan_module):
        result = rapidscan_module.url_maker("http://example.com/path?q=1")
        assert result == "example.com"

    def test_url_with_fragment(self, rapidscan_module):
        result = rapidscan_module.url_maker("http://example.com/path#section")
        assert result == "example.com"

    def test_url_with_auth(self, rapidscan_module):
        # urlsplit includes userinfo in netloc, so url_maker preserves it
        result = rapidscan_module.url_maker("http://user:pass@example.com")
        assert result == "user:pass@example.com"

    def test_ftp_scheme(self, rapidscan_module):
        # Non-http scheme - the regex doesn't match, so 'http://' is prepended
        result = rapidscan_module.url_maker("ftp://files.example.com")
        # http:// + ftp://files.example.com => netloc will be ftp:
        # Actually url_maker only adds http:// if no http(s): prefix
        assert isinstance(result, str)


# ---------------------------------------------------------------------------
# Tests for tool_status response codes
# ---------------------------------------------------------------------------
class TestToolStatusResponseCodes:
    """Validate tool_status response code values."""

    def test_response_codes_are_0_or_1(self, rapidscan_module):
        """Response code (arg2) should be 0 or 1."""
        for i, entry in enumerate(rapidscan_module.tool_status):
            assert entry[1] in (0, 1), \
                f"tool_status[{i}] has response code {entry[1]}, expected 0 or 1"

    def test_bad_responses_are_lists_or_strings(self, rapidscan_module):
        """Bad response entries (arg6) should be lists or strings."""
        for i, entry in enumerate(rapidscan_module.tool_status):
            assert isinstance(entry[5], (list, str)), \
                f"tool_status[{i}] bad response entry is not a list or string"

    def test_tool_status_identifiers_are_strings(self, rapidscan_module):
        """Tool status identifiers (arg5) should be non-empty strings."""
        for i, entry in enumerate(rapidscan_module.tool_status):
            assert isinstance(entry[4], str), \
                f"tool_status[{i}] identifier is not a string"
            assert len(entry[4]) > 0, \
                f"tool_status[{i}] identifier is empty"

    def test_tool_status_time_estimates_are_strings(self, rapidscan_module):
        """Time estimate entries (arg4) should be non-empty strings."""
        for i, entry in enumerate(rapidscan_module.tool_status):
            assert isinstance(entry[3], str), \
                f"tool_status[{i}] time estimate is not a string"
