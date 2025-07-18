import random
import re
import time
from module.error_manager import CaptureTimeout
from playwright.stealth import stealth_async, StealthConfig
from playwright.async_api import async_playwright, TimeoutError
from shared import app
from module.utils import HTTP_CONTEXT, get_proxy, get_device_useragent
import base64


def __init__(self):
    pass


def format_http_response(http_response):
    return {
        'url': http_response.url,
        'remoteAddress': http_response.remote_address,
        'status': http_response.status,
        'headers': http_response.headers
    }


def get_random_device_name():
    available_devices = [k for k, v in get_device_useragent().items() if 'desktop_macintosh' not in v['userAgent']]
    return random.choice(available_devices)


async def scrap(url: str, user_agent=None, proxy_server=get_proxy()):
    async with async_playwright() as playwright:
        response = None
        output = {}
        results = {}
        proxy = None
        proxy = await get_proxy_server_informations(proxy, proxy_server)
        
        # Création d'un contexte de navigation
        try:
            # Sélection d'un navigateur
            browser = await playwright.firefox.launch(proxy=proxy)
            
            # Création d'un context
            context = await browser.new_context(ignore_https_errors=True)
            
            # Ouverture d'une page
            page = await context.new_page()
            
            # Modification des paramètres de la page
            # TODO: peut être modifier le timeout ou temps de chargement sur certains sites ex: https://www.hugogo
            page.set_default_timeout(45000)
            
            # await page.set_extra_http_headers(HTTP_CONTEXT)
            
            # Ajout de header dans le contexte pour plus de furtivité
            await context.set_extra_http_headers(HTTP_CONTEXT)
            
            # Récupération aléatoire d'un User Agent
            device_name = user_agent or get_random_device_name()
            
            # Ajout de la lib stealth pour plus de furtivité
            stealth_config = StealthConfig(
                nav_user_agent=device_name)
            
            await stealth_async(page, stealth_config)
        except Exception as e:
            app.logger.error(
                f"Erreur lors de la création du contexte de navigation : {e}, url : {url}")
        
        # Navigation sur l'url et récupération des informations
        response = await fetch_information_from_url(browser, device_name, page, response, results, url)
        
        try:
            # Récupération d'une image du site
            screenshot_bytes = await page.screenshot(full_page=False)
        except TimeoutError as e:
            raise CaptureTimeout(e)
        except Exception as e:
            app.logger.error(
                f"Erreur lors du screenshot de la page : {e}, url : {url}")
        
        await screenshot_encoding64(results, screenshot_bytes, url)
        
        output['data'] = results
        output['return_code'] = response.status
        
        # On ferme tous
        await page.close()
        await context.close()
        await browser.close()
        return output


async def screenshot_encoding64(results, screenshot_bytes, url):
    if screenshot_bytes:
        # Transformation de cette image en base 64 afin de la transporter
        try:
            results['screenshot'] = base64.b64encode(
                screenshot_bytes).decode()
        except Exception as e:
            app.logger.error(
                f"Erreur lors de l'encodage en base 64 du screenshot : {e}, url : {url}")


async def fetch_information_from_url(browser, device_name, page, response, results, url):
    try:
        # Naviguer vers l'URL désirée et attendre que la page soit chargée
        response = await page.goto(url, wait_until='load')
        # On attend 3 second que la page se charge un peu plus
        time.sleep(3)
    except TimeoutError as e:
        raise CaptureTimeout(e)
    except Exception as e:
        app.logger.error(
            f"Erreur inconnue pendant la navigation vers la page : {e}, url : {url}")
    
    # Récupération des informations nécessaire
    if response:
        results['url'] = page.url
        results['page_title'] = await page.title()
        results['browser_version'] = browser.version
        results['content'] = await page.main_frame.content()
        results['html_content'] = await page.content()
        results['html_content_length'] = len(results['html_content'])
        results['ok'] = response.ok
        results['all_headers'] = await response.all_headers()
        results['ipaddress'] = await response.server_addr()
        results['user_agent'] = device_name
    return response


async def get_proxy_server_informations(proxy, proxy_server):
    if proxy_server:
        proxy = {
            "server": app.config['PROXY_HOST'],
            "username": app.config['PROXY_AUTH'].split(':')[0],
            "password": app.config['PROXY_AUTH'].split(':')[1]
        }
    else:
        app.logger.error("Le format du proxy_server est invalide.")
    return proxy

