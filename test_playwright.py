"""
Unit tests for playwright_reconstituted.py module.

This test suite covers all functions in the playwright_reconstituted module
with proper mocking of external dependencies like Playwright, Flask app,
and network requests.
"""

import pytest
import asyncio
import base64
from unittest.mock import Mock, AsyncMock, patch, MagicMock
from playwright.async_api import TimeoutError

# Import the module under test
import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Mock the dependencies before importing the module
with patch('shared.app') as mock_app:
    mock_app.logger = Mock()
    mock_app.config = {
        'PROXY_HOST': 'proxy.example.com:8080',
        'PROXY_AUTH': 'username:password'
    }
    
    with patch('module.error_manager.CaptureTimeout'):
        with patch('module.utils.HTTP_CONTEXT', {}):
            with patch('module.utils.get_proxy', return_value=True):
                with patch('module.utils.get_device_useragent', return_value={
                    'iPhone 12': {'userAgent': 'Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X)'},
                    'desktop_macintosh': {'userAgent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)'},
                    'Samsung Galaxy S21': {'userAgent': 'Mozilla/5.0 (Linux; Android 11; SM-G991B)'}
                }):
                    import playwright_reconstituted


class TestPlaywrightReconstituted:
    """Test class for playwright_reconstituted module functions."""
    
    @pytest.fixture
    def mock_http_response(self):
        """Create a mock HTTP response object."""
        mock_response = Mock()
        mock_response.url = "https://example.com"
        mock_response.remote_address = "192.168.1.1:443"
        mock_response.status = 200
        mock_response.headers = {"content-type": "text/html", "server": "nginx"}
        mock_response.ok = True
        mock_response.all_headers = AsyncMock(return_value={"content-type": "text/html"})
        mock_response.server_addr = AsyncMock(return_value="192.168.1.1:443")
        return mock_response
    
    @pytest.fixture
    def mock_page(self):
        """Create a mock Playwright page object."""
        mock_page = AsyncMock()
        mock_page.url = "https://example.com"
        mock_page.title = AsyncMock(return_value="Example Page")
        mock_page.content = AsyncMock(return_value="<html><body>Test content</body></html>")
        mock_page.main_frame.content = AsyncMock(return_value="<html><body>Test content</body></html>")
        mock_page.screenshot = AsyncMock(return_value=b"fake_screenshot_data")
        mock_page.goto = AsyncMock()
        mock_page.set_default_timeout = Mock()
        mock_page.close = AsyncMock()
        return mock_page
    
    @pytest.fixture
    def mock_context(self):
        """Create a mock Playwright context object."""
        mock_context = AsyncMock()
        mock_context.new_page = AsyncMock()
        mock_context.set_extra_http_headers = AsyncMock()
        mock_context.close = AsyncMock()
        return mock_context
    
    @pytest.fixture
    def mock_browser(self):
        """Create a mock Playwright browser object."""
        mock_browser = AsyncMock()
        mock_browser.version = "Firefox 95.0"
        mock_browser.new_context = AsyncMock()
        mock_browser.close = AsyncMock()
        return mock_browser
    
    @pytest.fixture
    def mock_playwright(self, mock_browser, mock_context, mock_page):
        """Create a mock Playwright instance."""
        mock_playwright = AsyncMock()
        mock_playwright.firefox.launch = AsyncMock(return_value=mock_browser)
        mock_browser.new_context.return_value = mock_context
        mock_context.new_page.return_value = mock_page
        return mock_playwright



    # Tests for utility functions
    
    def test_format_http_response(self, mock_http_response):
        """Test format_http_response function with a mock HTTP response."""
        result = playwright_reconstituted.format_http_response(mock_http_response)
        
        expected = {
            'url': 'https://example.com',
            'remoteAddress': '192.168.1.1:443',
            'status': 200,
            'headers': {'content-type': 'text/html', 'server': 'nginx'}
        }
        
        assert result == expected
        assert isinstance(result, dict)
        assert 'url' in result
        assert 'remoteAddress' in result
        assert 'status' in result
        assert 'headers' in result
    
    def test_format_http_response_with_different_status(self):
        """Test format_http_response with different HTTP status codes."""
        mock_response = Mock()
        mock_response.url = "https://notfound.com"
        mock_response.remote_address = "10.0.0.1:80"
        mock_response.status = 404
        mock_response.headers = {"content-type": "text/html"}
        
        result = playwright_reconstituted.format_http_response(mock_response)
        
        assert result['status'] == 404
        assert result['url'] == "https://notfound.com"
        assert result['remoteAddress'] == "10.0.0.1:80"
    
    @patch('playwright_reconstituted.get_device_useragent')
    @patch('playwright_reconstituted.random.choice')
    def test_get_random_device_name(self, mock_choice, mock_get_device_useragent):
        """Test get_random_device_name function."""
        # Mock the device user agent data
        mock_get_device_useragent.return_value = {
            'iPhone 12': {'userAgent': 'Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X)'},
            'desktop_macintosh': {'userAgent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)'},
            'Samsung Galaxy S21': {'userAgent': 'Mozilla/5.0 (Linux; Android 11; SM-G991B)'},
            'iPad Pro': {'userAgent': 'Mozilla/5.0 (iPad; CPU OS 14_0 like Mac OS X)'}
        }
        
        # Mock random.choice to return a specific device
        mock_choice.return_value = 'iPhone 12'
        
        result = playwright_reconstituted.get_random_device_name()
        
        # Verify that desktop_macintosh is filtered out
        available_devices = ['iPhone 12', 'Samsung Galaxy S21', 'iPad Pro']
        mock_choice.assert_called_once_with(available_devices)
        assert result == 'iPhone 12'
    
    @patch('playwright_reconstituted.get_device_useragent')
    def test_get_random_device_name_filters_desktop_macintosh(self, mock_get_device_useragent):
        """Test that get_random_device_name filters out desktop_macintosh devices."""
        mock_get_device_useragent.return_value = {
            'desktop_macintosh': {'userAgent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)'},
            'iPhone 12': {'userAgent': 'Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X)'}
        }
        
        with patch('playwright_reconstituted.random.choice') as mock_choice:
            mock_choice.return_value = 'iPhone 12'
            result = playwright_reconstituted.get_random_device_name()
            
            # Verify only non-desktop_macintosh devices are passed to choice
            called_devices = mock_choice.call_args[0][0]
            assert 'desktop_macintosh' not in called_devices
            assert 'iPhone 12' in called_devices
    
    @pytest.mark.asyncio
    async def test_get_proxy_server_informations_with_proxy(self):
        """Test get_proxy_server_informations when proxy_server is True."""
        with patch('playwright_reconstituted.app') as mock_app:
            mock_app.config = {
                'PROXY_HOST': 'proxy.example.com:8080',
                'PROXY_AUTH': 'username:password'
            }
            
            result = await playwright_reconstituted.get_proxy_server_informations(None, True)
            
            expected = {
                "server": "proxy.example.com:8080",
                "username": "username",
                "password": "password"
            }
            
            assert result == expected
    
    @pytest.mark.asyncio
    async def test_get_proxy_server_informations_without_proxy(self):
        """Test get_proxy_server_informations when proxy_server is False."""
        with patch('playwright_reconstituted.app') as mock_app:
            mock_app.logger = Mock()
            
            result = await playwright_reconstituted.get_proxy_server_informations(None, False)
            
            assert result is None
            mock_app.logger.error.assert_called_once_with("Le format du proxy_server est invalide.")
    
    @pytest.mark.asyncio
    async def test_get_proxy_server_informations_with_existing_proxy(self):
        """Test get_proxy_server_informations when proxy is already provided."""
        existing_proxy = {"server": "existing.proxy.com"}
        
        result = await playwright_reconstituted.get_proxy_server_informations(existing_proxy, True)
        
        # Should return the existing proxy when one is already provided
        assert result == existing_proxy


    # Tests for async functions
    
    @pytest.mark.asyncio
    async def test_screenshot_encoding64_success(self):
        """Test screenshot_encoding64 function with valid screenshot data."""
        results = {}
        screenshot_bytes = b"fake_screenshot_data"
        url = "https://example.com"
        
        await playwright_reconstituted.screenshot_encoding64(results, screenshot_bytes, url)
        
        expected_base64 = base64.b64encode(screenshot_bytes).decode()
        assert 'screenshot' in results
        assert results['screenshot'] == expected_base64
    
    @pytest.mark.asyncio
    async def test_screenshot_encoding64_with_none_bytes(self):
        """Test screenshot_encoding64 function with None screenshot bytes."""
        results = {}
        screenshot_bytes = None
        url = "https://example.com"
        
        await playwright_reconstituted.screenshot_encoding64(results, screenshot_bytes, url)
        
        # Should not add screenshot key when bytes is None
        assert 'screenshot' not in results
    
    @pytest.mark.asyncio
    async def test_screenshot_encoding64_encoding_error(self):
        """Test screenshot_encoding64 function when base64 encoding fails."""
        results = {}
        # Create an object that will cause base64 encoding to fail
        screenshot_bytes = "invalid_bytes_object"
        url = "https://example.com"
        
        with patch('playwright_reconstituted.app') as mock_app:
            mock_app.logger = Mock()
            
            await playwright_reconstituted.screenshot_encoding64(results, screenshot_bytes, url)
            
            # Should log error and not add screenshot to results
            mock_app.logger.error.assert_called_once()
            assert 'screenshot' not in results
    
    @pytest.mark.asyncio
    async def test_fetch_information_from_url_success(self, mock_browser, mock_page, mock_http_response):
        """Test fetch_information_from_url function with successful navigation."""
        device_name = "iPhone 12"
        response = None
        results = {}
        url = "https://example.com"
        
        # Setup mock page responses
        mock_page.goto.return_value = mock_http_response
        mock_page.url = "https://example.com"
        mock_page.title.return_value = "Example Page"
        mock_page.main_frame.content.return_value = "<html><body>Test content</body></html>"
        mock_page.content.return_value = "<html><body>Test content</body></html>"
        mock_browser.version = "Firefox 95.0"
        
        with patch('playwright_reconstituted.time.sleep'):
            result = await playwright_reconstituted.fetch_information_from_url(
                mock_browser, device_name, mock_page, response, results, url
            )
        
        # Verify the function was called correctly
        mock_page.goto.assert_called_once_with(url, wait_until='load')
        
        # Verify results are populated
        assert results['url'] == "https://example.com"
        assert results['page_title'] == "Example Page"
        assert results['browser_version'] == "Firefox 95.0"
        assert results['content'] == "<html><body>Test content</body></html>"
        assert results['html_content'] == "<html><body>Test content</body></html>"
        assert results['html_content_length'] == len("<html><body>Test content</body></html>")
        assert results['ok'] == True
        assert results['user_agent'] == device_name
        
        # Verify the response is returned
        assert result == mock_http_response
    
    @pytest.mark.asyncio
    async def test_fetch_information_from_url_timeout_error(self, mock_browser, mock_page):
        """Test fetch_information_from_url function when TimeoutError occurs."""
        device_name = "iPhone 12"
        response = None
        results = {}
        url = "https://example.com"
        
        # Setup mock to raise TimeoutError
        mock_page.goto.side_effect = TimeoutError("Navigation timeout")
        
        with patch('playwright_reconstituted.CaptureTimeout') as mock_capture_timeout:
            with pytest.raises(Exception):  # CaptureTimeout should be raised
                await playwright_reconstituted.fetch_information_from_url(
                    mock_browser, device_name, mock_page, response, results, url
                )
            
            mock_capture_timeout.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_fetch_information_from_url_general_exception(self, mock_browser, mock_page):
        """Test fetch_information_from_url function when general exception occurs."""
        device_name = "iPhone 12"
        response = None
        results = {}
        url = "https://example.com"
        
        # Setup mock to raise general exception
        mock_page.goto.side_effect = Exception("Network error")
        
        with patch('playwright_reconstituted.app') as mock_app:
            mock_app.logger = Mock()
            
            result = await playwright_reconstituted.fetch_information_from_url(
                mock_browser, device_name, mock_page, response, results, url
            )
            
            # Should log error and return None
            mock_app.logger.error.assert_called_once()
            assert result is None
    
    @pytest.mark.asyncio
    @patch('playwright_reconstituted.async_playwright')
    @patch('playwright_reconstituted.stealth_async')
    @patch('playwright_reconstituted.get_proxy_server_informations')
    @patch('playwright_reconstituted.fetch_information_from_url')
    @patch('playwright_reconstituted.screenshot_encoding64')
    @patch('playwright_reconstituted.get_random_device_name')
    @patch('playwright_reconstituted.time.sleep')
    async def test_scrap_function_success(self, mock_sleep, mock_get_device, mock_screenshot, 
                                        mock_fetch, mock_get_proxy, mock_stealth, mock_playwright):
        """Test the main scrap function with successful execution."""
        url = "https://example.com"
        user_agent = "iPhone 12"
        proxy_server = True
        
        # Setup mocks
        mock_get_device.return_value = "iPhone 12"
        mock_get_proxy.return_value = {"server": "proxy.example.com"}
        
        # Setup playwright mocks
        mock_browser = AsyncMock()
        mock_context = AsyncMock()
        mock_page = AsyncMock()
        mock_response = Mock()
        mock_response.status = 200
        
        mock_playwright_instance = AsyncMock()
        mock_playwright_instance.firefox.launch.return_value = mock_browser
        mock_browser.new_context.return_value = mock_context
        mock_context.new_page.return_value = mock_page
        mock_page.screenshot.return_value = b"screenshot_data"
        
        mock_playwright.return_value.__aenter__.return_value = mock_playwright_instance
        mock_fetch.return_value = mock_response
        
        # Execute the function
        result = await playwright_reconstituted.scrap(url, user_agent, proxy_server)
        
        # Verify the result structure
        assert 'data' in result
        assert 'return_code' in result
        assert result['return_code'] == 200
        
        # Verify function calls
        mock_playwright_instance.firefox.launch.assert_called_once()
        mock_browser.new_context.assert_called_once()
        mock_context.new_page.assert_called_once()
        mock_page.set_default_timeout.assert_called_once_with(45000)
        mock_context.set_extra_http_headers.assert_called_once()
        mock_stealth.assert_called_once()
        mock_fetch.assert_called_once()
        mock_screenshot.assert_called_once()
        
        # Verify cleanup
        mock_page.close.assert_called_once()
        mock_context.close.assert_called_once()
        mock_browser.close.assert_called_once()
    
    @pytest.mark.asyncio
    @patch('playwright_reconstituted.async_playwright')
    @patch('playwright_reconstituted.get_proxy_server_informations')
    async def test_scrap_function_browser_creation_error(self, mock_get_proxy, mock_playwright):
        """Test scrap function when browser creation fails."""
        url = "https://example.com"
        
        mock_get_proxy.return_value = None
        mock_playwright_instance = AsyncMock()
        mock_playwright_instance.firefox.launch.side_effect = Exception("Browser launch failed")
        mock_playwright.return_value.__aenter__.return_value = mock_playwright_instance
        
        with patch('playwright_reconstituted.app') as mock_app:
            mock_app.logger = Mock()
            
            # The function should handle the exception and continue
            result = await playwright_reconstituted.scrap(url)
            
            # Should log the error
            mock_app.logger.error.assert_called()
    
    @pytest.mark.asyncio
    @patch('playwright_reconstituted.async_playwright')
    @patch('playwright_reconstituted.stealth_async')
    @patch('playwright_reconstituted.get_proxy_server_informations')
    @patch('playwright_reconstituted.fetch_information_from_url')
    async def test_scrap_function_screenshot_timeout(self, mock_fetch, mock_get_proxy, 
                                                   mock_stealth, mock_playwright):
        """Test scrap function when screenshot times out."""
        url = "https://example.com"
        
        # Setup mocks
        mock_get_proxy.return_value = None
        mock_response = Mock()
        mock_response.status = 200
        mock_fetch.return_value = mock_response
        
        # Setup playwright mocks
        mock_browser = AsyncMock()
        mock_context = AsyncMock()
        mock_page = AsyncMock()
        
        mock_playwright_instance = AsyncMock()
        mock_playwright_instance.firefox.launch.return_value = mock_browser
        mock_browser.new_context.return_value = mock_context
        mock_context.new_page.return_value = mock_page
        
        # Make screenshot raise TimeoutError
        mock_page.screenshot.side_effect = TimeoutError("Screenshot timeout")
        
        mock_playwright.return_value.__aenter__.return_value = mock_playwright_instance
        
        with patch('playwright_reconstituted.CaptureTimeout') as mock_capture_timeout:
            with pytest.raises(Exception):  # CaptureTimeout should be raised
                await playwright_reconstituted.scrap(url)
            
            mock_capture_timeout.assert_called_once()
    
    @pytest.mark.asyncio
    @patch('playwright_reconstituted.async_playwright')
    @patch('playwright_reconstituted.stealth_async')
    @patch('playwright_reconstituted.get_proxy_server_informations')
    @patch('playwright_reconstituted.fetch_information_from_url')
    async def test_scrap_function_screenshot_general_error(self, mock_fetch, mock_get_proxy, 
                                                         mock_stealth, mock_playwright):
        """Test scrap function when screenshot fails with general error."""
        url = "https://example.com"
        
        # Setup mocks
        mock_get_proxy.return_value = None
        mock_response = Mock()
        mock_response.status = 200
        mock_fetch.return_value = mock_response
        
        # Setup playwright mocks
        mock_browser = AsyncMock()
        mock_context = AsyncMock()
        mock_page = AsyncMock()
        
        mock_playwright_instance = AsyncMock()
        mock_playwright_instance.firefox.launch.return_value = mock_browser
        mock_browser.new_context.return_value = mock_context
        mock_context.new_page.return_value = mock_page
        
        # Make screenshot raise general exception
        mock_page.screenshot.side_effect = Exception("Screenshot failed")
        
        mock_playwright.return_value.__aenter__.return_value = mock_playwright_instance
        
        with patch('playwright_reconstituted.app') as mock_app:
            mock_app.logger = Mock()
            
            # Function should continue and log the error
            result = await playwright_reconstituted.scrap(url)
            
            mock_app.logger.error.assert_called()
            assert result['return_code'] == 200


    # Additional test fixtures and edge cases
    
    @pytest.fixture
    def sample_device_useragents(self):
        """Sample device user agents for testing."""
        return {
            'iPhone 12': {
                'userAgent': 'Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X) AppleWebKit/605.1.15'
            },
            'desktop_macintosh': {
                'userAgent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36'
            },
            'Samsung Galaxy S21': {
                'userAgent': 'Mozilla/5.0 (Linux; Android 11; SM-G991B) AppleWebKit/537.36'
            },
            'iPad Pro': {
                'userAgent': 'Mozilla/5.0 (iPad; CPU OS 14_0 like Mac OS X) AppleWebKit/605.1.15'
            }
        }
    
    @pytest.fixture
    def mock_stealth_config(self):
        """Mock stealth configuration."""
        return Mock()
    
    # Edge case tests
    
    def test_format_http_response_with_none_values(self):
        """Test format_http_response with None values in response."""
        mock_response = Mock()
        mock_response.url = None
        mock_response.remote_address = None
        mock_response.status = None
        mock_response.headers = None
        
        result = playwright_reconstituted.format_http_response(mock_response)
        
        assert result['url'] is None
        assert result['remoteAddress'] is None
        assert result['status'] is None
        assert result['headers'] is None
    
    @patch('playwright_reconstituted.get_device_useragent')
    def test_get_random_device_name_empty_list(self, mock_get_device_useragent):
        """Test get_random_device_name when all devices are filtered out."""
        # Only desktop_macintosh devices
        mock_get_device_useragent.return_value = {
            'desktop_macintosh_1': {'userAgent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)'},
            'desktop_macintosh_2': {'userAgent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 11_0_0)'}
        }
        
        with patch('playwright_reconstituted.random.choice') as mock_choice:
            mock_choice.side_effect = IndexError("list index out of range")
            
            with pytest.raises(IndexError):
                playwright_reconstituted.get_random_device_name()
    
    @pytest.mark.asyncio
    async def test_get_proxy_server_informations_malformed_auth(self):
        """Test get_proxy_server_informations with malformed PROXY_AUTH."""
        with patch('playwright_reconstituted.app') as mock_app:
            mock_app.config = {
                'PROXY_HOST': 'proxy.example.com:8080',
                'PROXY_AUTH': 'malformed_auth_string'  # No colon separator
            }
            mock_app.logger = Mock()
            
            # This should raise an IndexError when trying to split
            with pytest.raises(IndexError):
                await playwright_reconstituted.get_proxy_server_informations(None, True)
    
    @pytest.mark.asyncio
    async def test_fetch_information_from_url_no_response(self, mock_browser, mock_page):
        """Test fetch_information_from_url when goto returns None."""
        device_name = "iPhone 12"
        response = None
        results = {}
        url = "https://example.com"
        
        # Setup mock to return None (no response)
        mock_page.goto.return_value = None
        
        with patch('playwright_reconstituted.time.sleep'):
            result = await playwright_reconstituted.fetch_information_from_url(
                mock_browser, device_name, mock_page, response, results, url
            )
        
        # Should return None and not populate results
        assert result is None
        assert len(results) == 0
    
    @pytest.mark.asyncio
    async def test_screenshot_encoding64_empty_bytes(self):
        """Test screenshot_encoding64 with empty bytes."""
        results = {}
        screenshot_bytes = b""
        url = "https://example.com"
        
        await playwright_reconstituted.screenshot_encoding64(results, screenshot_bytes, url)
        
        # Should encode empty bytes successfully
        expected_base64 = base64.b64encode(b"").decode()
        assert results['screenshot'] == expected_base64
        assert results['screenshot'] == ""
    
    # Integration-style tests
    
    @pytest.mark.asyncio
    @patch('playwright_reconstituted.async_playwright')
    async def test_scrap_function_minimal_success(self, mock_playwright):
        """Test scrap function with minimal successful execution."""
        url = "https://example.com"
        
        # Setup minimal mocks
        mock_browser = AsyncMock()
        mock_context = AsyncMock()
        mock_page = AsyncMock()
        mock_response = Mock()
        mock_response.status = 200
        
        mock_playwright_instance = AsyncMock()
        mock_playwright_instance.firefox.launch.return_value = mock_browser
        mock_browser.new_context.return_value = mock_context
        mock_context.new_page.return_value = mock_page
        mock_page.goto.return_value = mock_response
        mock_page.screenshot.return_value = b"test"
        
        mock_playwright.return_value.__aenter__.return_value = mock_playwright_instance
        
        with patch('playwright_reconstituted.get_proxy_server_informations', return_value=None):
            with patch('playwright_reconstituted.get_random_device_name', return_value="iPhone 12"):
                with patch('playwright_reconstituted.stealth_async'):
                    with patch('playwright_reconstituted.time.sleep'):
                        result = await playwright_reconstituted.scrap(url)
        
        assert 'data' in result
        assert 'return_code' in result
        assert result['return_code'] == 200
    
    # Performance and boundary tests
    
    @pytest.mark.asyncio
    async def test_screenshot_encoding64_large_data(self):
        """Test screenshot_encoding64 with large screenshot data."""
        results = {}
        # Create large fake screenshot data (1MB)
        screenshot_bytes = b"x" * (1024 * 1024)
        url = "https://example.com"
        
        await playwright_reconstituted.screenshot_encoding64(results, screenshot_bytes, url)
        
        # Should handle large data successfully
        assert 'screenshot' in results
        assert len(results['screenshot']) > 0
        # Verify it's valid base64
        decoded = base64.b64decode(results['screenshot'])
        assert decoded == screenshot_bytes
    
    def test_format_http_response_with_complex_headers(self):
        """Test format_http_response with complex header structure."""
        mock_response = Mock()
        mock_response.url = "https://api.example.com/v1/data"
        mock_response.remote_address = "203.0.113.1:443"
        mock_response.status = 201
        mock_response.headers = {
            "content-type": "application/json; charset=utf-8",
            "cache-control": "no-cache, no-store, must-revalidate",
            "x-custom-header": "custom-value",
            "set-cookie": "session=abc123; HttpOnly; Secure"
        }
        
        result = playwright_reconstituted.format_http_response(mock_response)
        
        assert result['status'] == 201
        assert result['headers']['content-type'] == "application/json; charset=utf-8"
        assert result['headers']['x-custom-header'] == "custom-value"
        assert len(result['headers']) == 4


# Test configuration and runner
if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])

