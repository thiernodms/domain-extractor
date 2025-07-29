import pytest
import asyncio
import base64
import time
from unittest.mock import AsyncMock, MagicMock, patch, call
from playwright.async_api import TimeoutError as PlaywrightTimeoutError

# Import de la fonction à tester (à adapter selon votre structure)
# from your_module import scrap, CaptureTimeout, get_proxy, get_random_device_name, StealthConfig, stealth_async, HTTP_CONTEXT, app


class CaptureTimeout(Exception):
    """Exception personnalisée pour les timeouts de capture"""
    pass


@pytest.fixture
def mock_app():
    """Mock de l'objet app Flask"""
    app = MagicMock()
    app.config = {
        'PROXY_HOST': 'proxy.example.com:8080',
        'PROXY_AUTH': 'username:password'
    }
    app.logger = MagicMock()
    return app


@pytest.fixture
def mock_playwright():
    """Mock complet de Playwright"""
    playwright = MagicMock()
    browser = AsyncMock()
    context = AsyncMock()
    page = AsyncMock()
    response = AsyncMock()
    
    # Configuration des mocks
    playwright.firefox.launch = AsyncMock(return_value=browser)
    browser.new_context = AsyncMock(return_value=context)
    browser.version = "Firefox 120.0"
    browser.close = AsyncMock()
    
    context.new_page = AsyncMock(return_value=page)
    context.set_extra_http_headers = AsyncMock()
    context.close = AsyncMock()
    
    page.set_default_timeout = MagicMock()
    page.goto = AsyncMock(return_value=response)
    page.url = "https://example.com"
    page.title = AsyncMock(return_value="Test Page Title")
    page.main_frame.content = AsyncMock(return_value="<html>content</html>")
    page.content = AsyncMock(return_value="<html>full content</html>")
    page.screenshot = AsyncMock(return_value=b"fake_screenshot_data")
    page.close = AsyncMock()
    
    response.ok = True
    response.status = 200
    response.all_headers = AsyncMock(return_value={"content-type": "text/html"})
    response.server_addr = AsyncMock(return_value="192.168.1.1")
    
    return playwright, browser, context, page, response


@pytest.fixture
def mock_dependencies():
    """Mock des dépendances externes"""
    return {
        'get_proxy': MagicMock(return_value="proxy_config"),
        'get_random_device_name': MagicMock(return_value="Mozilla/5.0 Random Agent"),
        'StealthConfig': MagicMock(),
        'stealth_async': AsyncMock(),
        'HTTP_CONTEXT': {"User-Agent": "Test Agent"}
    }


class TestScrap:
    """Tests unitaires pour la fonction scrap"""
    
    @pytest.mark.asyncio
    async def test_scrap_success_with_proxy_and_user_agent(self, mock_app, mock_playwright, mock_dependencies):
        """Test du cas de succès complet avec proxy et user_agent"""
        playwright, browser, context, page, response = mock_playwright
        
        with patch('your_module.async_playwright') as mock_async_playwright, \
             patch('your_module.app', mock_app), \
             patch('your_module.get_proxy', mock_dependencies['get_proxy']), \
             patch('your_module.get_random_device_name', mock_dependencies['get_random_device_name']), \
             patch('your_module.StealthConfig', mock_dependencies['StealthConfig']), \
             patch('your_module.stealth_async', mock_dependencies['stealth_async']), \
             patch('your_module.HTTP_CONTEXT', mock_dependencies['HTTP_CONTEXT']), \
             patch('your_module.time.sleep'), \
             patch('your_module.base64.b64encode', return_value=b'encoded_screenshot'):
            
            mock_async_playwright.return_value.__aenter__.return_value = playwright
            
            # Appel de la fonction
            result = await scrap("https://example.com", user_agent="Custom Agent")
            
            # Vérifications
            assert result['return_code'] == 200
            assert result['data']['url'] == "https://example.com"
            assert result['data']['page_title'] == "Test Page Title"
            assert result['data']['user_agent'] == "Custom Agent"
            assert result['data']['screenshot'] == 'encoded_screenshot'
            
            # Vérification des appels
            playwright.firefox.launch.assert_called_once_with(proxy={
                "server": "proxy.example.com:8080",
                "username": "username",
                "password": "password"
            })
            page.goto.assert_called_once_with("https://example.com", wait_until='load')
            page.screenshot.assert_called_once_with(full_page=False)
    
    @pytest.mark.asyncio
    async def test_scrap_success_without_proxy(self, mock_app, mock_playwright, mock_dependencies):
        """Test du succès sans proxy"""
        playwright, browser, context, page, response = mock_playwright
        mock_dependencies['get_proxy'].return_value = None
        
        with patch('your_module.async_playwright') as mock_async_playwright, \
             patch('your_module.app', mock_app), \
             patch('your_module.get_proxy', mock_dependencies['get_proxy']), \
             patch('your_module.get_random_device_name', mock_dependencies['get_random_device_name']), \
             patch('your_module.StealthConfig', mock_dependencies['StealthConfig']), \
             patch('your_module.stealth_async', mock_dependencies['stealth_async']), \
             patch('your_module.HTTP_CONTEXT', mock_dependencies['HTTP_CONTEXT']), \
             patch('your_module.time.sleep'), \
             patch('your_module.base64.b64encode', return_value=b'encoded_screenshot'):
            
            mock_async_playwright.return_value.__aenter__.return_value = playwright
            
            result = await scrap("https://example.com")
            
            # Vérification que le proxy est None
            playwright.firefox.launch.assert_called_once_with(proxy=None)
            mock_app.logger.error.assert_called_once_with("Le format du proxy_server est invalide.")
    
    @pytest.mark.asyncio
    async def test_scrap_success_without_user_agent(self, mock_app, mock_playwright, mock_dependencies):
        """Test du succès sans user_agent (utilisation de get_random_device_name)"""
        playwright, browser, context, page, response = mock_playwright
        
        with patch('your_module.async_playwright') as mock_async_playwright, \
             patch('your_module.app', mock_app), \
             patch('your_module.get_proxy', mock_dependencies['get_proxy']), \
             patch('your_module.get_random_device_name', mock_dependencies['get_random_device_name']), \
             patch('your_module.StealthConfig', mock_dependencies['StealthConfig']), \
             patch('your_module.stealth_async', mock_dependencies['stealth_async']), \
             patch('your_module.HTTP_CONTEXT', mock_dependencies['HTTP_CONTEXT']), \
             patch('your_module.time.sleep'), \
             patch('your_module.base64.b64encode', return_value=b'encoded_screenshot'):
            
            mock_async_playwright.return_value.__aenter__.return_value = playwright
            
            result = await scrap("https://example.com")
            
            # Vérification que get_random_device_name a été appelé
            mock_dependencies['get_random_device_name'].assert_called_once()
            assert result['data']['user_agent'] == "Mozilla/5.0 Random Agent"
    
    @pytest.mark.asyncio
    async def test_scrap_browser_creation_exception(self, mock_app, mock_playwright, mock_dependencies):
        """Test de l'exception lors de la création du navigateur"""
        playwright, browser, context, page, response = mock_playwright
        playwright.firefox.launch.side_effect = Exception("Browser launch failed")
        
        with patch('your_module.async_playwright') as mock_async_playwright, \
             patch('your_module.app', mock_app), \
             patch('your_module.get_proxy', mock_dependencies['get_proxy']), \
             patch('your_module.get_random_device_name', mock_dependencies['get_random_device_name']), \
             patch('your_module.StealthConfig', mock_dependencies['StealthConfig']), \
             patch('your_module.stealth_async', mock_dependencies['stealth_async']), \
             patch('your_module.HTTP_CONTEXT', mock_dependencies['HTTP_CONTEXT']):
            
            mock_async_playwright.return_value.__aenter__.return_value = playwright
            
            # L'exception devrait être gérée et loggée
            with pytest.raises(AttributeError):  # Car page n'existe pas après l'exception
                await scrap("https://example.com")
            
            mock_app.logger.error.assert_called()
    
    @pytest.mark.asyncio
    async def test_scrap_navigation_timeout_error(self, mock_app, mock_playwright, mock_dependencies):
        """Test du TimeoutError lors de la navigation"""
        playwright, browser, context, page, response = mock_playwright
        page.goto.side_effect = PlaywrightTimeoutError("Navigation timeout")
        
        with patch('your_module.async_playwright') as mock_async_playwright, \
             patch('your_module.app', mock_app), \
             patch('your_module.get_proxy', mock_dependencies['get_proxy']), \
             patch('your_module.get_random_device_name', mock_dependencies['get_random_device_name']), \
             patch('your_module.StealthConfig', mock_dependencies['StealthConfig']), \
             patch('your_module.stealth_async', mock_dependencies['stealth_async']), \
             patch('your_module.HTTP_CONTEXT', mock_dependencies['HTTP_CONTEXT']), \
             patch('your_module.CaptureTimeout', CaptureTimeout):
            
            mock_async_playwright.return_value.__aenter__.return_value = playwright
            
            with pytest.raises(CaptureTimeout):
                await scrap("https://example.com")
    
    @pytest.mark.asyncio
    async def test_scrap_navigation_general_exception(self, mock_app, mock_playwright, mock_dependencies):
        """Test d'une exception générale lors de la navigation"""
        playwright, browser, context, page, response = mock_playwright
        page.goto.side_effect = Exception("Network error")
        
        with patch('your_module.async_playwright') as mock_async_playwright, \
             patch('your_module.app', mock_app), \
             patch('your_module.get_proxy', mock_dependencies['get_proxy']), \
             patch('your_module.get_random_device_name', mock_dependencies['get_random_device_name']), \
             patch('your_module.StealthConfig', mock_dependencies['StealthConfig']), \
             patch('your_module.stealth_async', mock_dependencies['stealth_async']), \
             patch('your_module.HTTP_CONTEXT', mock_dependencies['HTTP_CONTEXT']), \
             patch('your_module.time.sleep'), \
             patch('your_module.base64.b64encode', return_value=b'encoded_screenshot'):
            
            mock_async_playwright.return_value.__aenter__.return_value = playwright
            
            result = await scrap("https://example.com")
            
            # Vérification que l'erreur est loggée
            mock_app.logger.error.assert_any_call(
                "Erreur inconnue pendant la navigation vers la page : Network error, url : https://example.com"
            )
            
            # Le résultat devrait avoir response None
            assert result['data'] == {}  # Pas de données car response est None
    
    @pytest.mark.asyncio
    async def test_scrap_response_none(self, mock_app, mock_playwright, mock_dependencies):
        """Test du cas où response est None"""
        playwright, browser, context, page, response = mock_playwright
        page.goto.return_value = None
        
        with patch('your_module.async_playwright') as mock_async_playwright, \
             patch('your_module.app', mock_app), \
             patch('your_module.get_proxy', mock_dependencies['get_proxy']), \
             patch('your_module.get_random_device_name', mock_dependencies['get_random_device_name']), \
             patch('your_module.StealthConfig', mock_dependencies['StealthConfig']), \
             patch('your_module.stealth_async', mock_dependencies['stealth_async']), \
             patch('your_module.HTTP_CONTEXT', mock_dependencies['HTTP_CONTEXT']), \
             patch('your_module.time.sleep'), \
             patch('your_module.base64.b64encode', return_value=b'encoded_screenshot'):
            
            mock_async_playwright.return_value.__aenter__.return_value = playwright
            
            result = await scrap("https://example.com")
            
            # Vérification que les données de response ne sont pas collectées
            assert 'url' not in result['data']
            assert 'page_title' not in result['data']
            # Mais le screenshot devrait être présent
            assert result['data']['screenshot'] == 'encoded_screenshot'
    
    @pytest.mark.asyncio
    async def test_scrap_screenshot_timeout_error(self, mock_app, mock_playwright, mock_dependencies):
        """Test du TimeoutError lors du screenshot"""
        playwright, browser, context, page, response = mock_playwright
        page.screenshot.side_effect = PlaywrightTimeoutError("Screenshot timeout")
        
        with patch('your_module.async_playwright') as mock_async_playwright, \
             patch('your_module.app', mock_app), \
             patch('your_module.get_proxy', mock_dependencies['get_proxy']), \
             patch('your_module.get_random_device_name', mock_dependencies['get_random_device_name']), \
             patch('your_module.StealthConfig', mock_dependencies['StealthConfig']), \
             patch('your_module.stealth_async', mock_dependencies['stealth_async']), \
             patch('your_module.HTTP_CONTEXT', mock_dependencies['HTTP_CONTEXT']), \
             patch('your_module.time.sleep'), \
             patch('your_module.CaptureTimeout', CaptureTimeout):
            
            mock_async_playwright.return_value.__aenter__.return_value = playwright
            
            with pytest.raises(CaptureTimeout):
                await scrap("https://example.com")
    
    @pytest.mark.asyncio
    async def test_scrap_screenshot_general_exception(self, mock_app, mock_playwright, mock_dependencies):
        """Test d'une exception générale lors du screenshot"""
        playwright, browser, context, page, response = mock_playwright
        page.screenshot.side_effect = Exception("Screenshot failed")
        
        with patch('your_module.async_playwright') as mock_async_playwright, \
             patch('your_module.app', mock_app), \
             patch('your_module.get_proxy', mock_dependencies['get_proxy']), \
             patch('your_module.get_random_device_name', mock_dependencies['get_random_device_name']), \
             patch('your_module.StealthConfig', mock_dependencies['StealthConfig']), \
             patch('your_module.stealth_async', mock_dependencies['stealth_async']), \
             patch('your_module.HTTP_CONTEXT', mock_dependencies['HTTP_CONTEXT']), \
             patch('your_module.time.sleep'), \
             patch('your_module.base64.b64encode', return_value=b'encoded_screenshot'):
            
            mock_async_playwright.return_value.__aenter__.return_value = playwright
            
            result = await scrap("https://example.com")
            
            # Vérification que l'erreur est loggée
            mock_app.logger.error.assert_any_call(
                "Erreur lors du screenshot de la page : Screenshot failed, url : https://example.com"
            )
            
            # Le screenshot ne devrait pas être dans les résultats
            assert 'screenshot' not in result['data']
    
    @pytest.mark.asyncio
    async def test_scrap_base64_encoding_exception(self, mock_app, mock_playwright, mock_dependencies):
        """Test d'une exception lors de l'encodage base64"""
        playwright, browser, context, page, response = mock_playwright
        
        with patch('your_module.async_playwright') as mock_async_playwright, \
             patch('your_module.app', mock_app), \
             patch('your_module.get_proxy', mock_dependencies['get_proxy']), \
             patch('your_module.get_random_device_name', mock_dependencies['get_random_device_name']), \
             patch('your_module.StealthConfig', mock_dependencies['StealthConfig']), \
             patch('your_module.stealth_async', mock_dependencies['stealth_async']), \
             patch('your_module.HTTP_CONTEXT', mock_dependencies['HTTP_CONTEXT']), \
             patch('your_module.time.sleep'), \
             patch('your_module.base64.b64encode', side_effect=Exception("Encoding failed")):
            
            mock_async_playwright.return_value.__aenter__.return_value = playwright
            
            result = await scrap("https://example.com")
            
            # Vérification que l'erreur est loggée
            mock_app.logger.error.assert_any_call(
                "Erreur lors de l'encodage en base 64 du screenshot : Encoding failed, url : https://example.com"
            )
            
            # Le screenshot ne devrait pas être dans les résultats
            assert 'screenshot' not in result['data']
    
    @pytest.mark.asyncio
    async def test_scrap_cleanup_calls(self, mock_app, mock_playwright, mock_dependencies):
        """Test que les ressources sont correctement nettoyées"""
        playwright, browser, context, page, response = mock_playwright
        
        with patch('your_module.async_playwright') as mock_async_playwright, \
             patch('your_module.app', mock_app), \
             patch('your_module.get_proxy', mock_dependencies['get_proxy']), \
             patch('your_module.get_random_device_name', mock_dependencies['get_random_device_name']), \
             patch('your_module.StealthConfig', mock_dependencies['StealthConfig']), \
             patch('your_module.stealth_async', mock_dependencies['stealth_async']), \
             patch('your_module.HTTP_CONTEXT', mock_dependencies['HTTP_CONTEXT']), \
             patch('your_module.time.sleep'), \
             patch('your_module.base64.b64encode', return_value=b'encoded_screenshot'):
            
            mock_async_playwright.return_value.__aenter__.return_value = playwright
            
            await scrap("https://example.com")
            
            # Vérification des appels de nettoyage
            page.close.assert_called_once()
            context.close.assert_called_once()
            browser.close.assert_called_once()


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--cov=your_module", "--cov-report=html", "--cov-report=term-missing"])

