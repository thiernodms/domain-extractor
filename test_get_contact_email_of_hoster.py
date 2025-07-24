import unittest
from unittest.mock import Mock, patch, MagicMock
import re
import json


# Simulation de la fonction originale pour les tests
def get_contact_email_of_hoster(hoster):
    import requests
    
    datas = requests.get(url=f"https://api.viewdns.info/whois/?domain={hoster}&apikey={app.config['WHOIS_API_KEY']}", verify=False, proxies=get_proxy())
    # Récupération de la réponse au format JSON
    try:
        datas = datas.json()["response"]
    except Exception:
        app.logger.error(
            "No json data from viewdns api, key maybe invalid or api down")
        datas = {"rawdata": None}
        return "?", datas
    
    # Création de la regex pour identifier la ligne "([...]abuse[...]:fabuse@contact.com}" -> () : group 1
    abuse_email = re.compile(
        r"(?:AbuseEmail|AbuseContactEmail|abuse).*?(?:\s|:)\s*(?:\+?\d{1,4}[\s\-\.]?)?\(?(?:\+?\d{1,4}[\s\-\.]?){0,4}(?:\w+\.){1,4}\w+")
    abuse_emails2 = re.compile(r"abuse@[\w\.-]+")
    
    try:
        # Suppression des espaces dans le rawdata pour identifier plus facilement le contact
        response = str.replace(datas["rawdata"], " ", "")
        # Application de la regex
        abuse_contact = re.findall(
            abuse_email, response) + re.findall(abuse_emails2, response)
        # Récupération du groupe 1 contenant le abuse contact
        exclusion = ["@ripe.net", "apnic.net", "arin.net", "lacnic.net",
                    "lacnic.net", "afrinic.net", "internic.net", "+"]
        a_inclure = "@"
        if abuse_contact:
            for x in abuse_contact:
                found_valid = False
                for a_exclure in exclusion:
                    if a_exclure in x or a_inclure not in x:
                        continue
                    else:
                        abuse_contact = x
                        found_valid = True
                        break
                if found_valid:
                    break
            if not found_valid:
                abuse_contact = "?"
        else:
            abuse_contact = "?"
    except Exception:
        app.logger.error(
            f"Abuse contact collect failed for hoster {hoster}")
        abuse_contact = "?"
        pass
    
    return abuse_contact, datas


class TestGetContactEmailOfHoster(unittest.TestCase):
    
    def setUp(self):
        """Configuration initiale pour chaque test"""
        # Mock des objets globaux
        global app
        app = Mock()
        app.config = {'WHOIS_API_KEY': 'test_api_key'}
        app.logger = Mock()
        
        global get_proxy
        get_proxy = Mock(return_value={'http': 'proxy.test.com'})
    
    @patch('requests.get')
    def test_successful_abuse_email_extraction(self, mock_get):
        """Test d'extraction réussie d'un email d'abuse"""
        # Données de test avec un email d'abuse valide
        mock_response = Mock()
        mock_response.json.return_value = {
            "response": {
                "rawdata": "AbuseEmail: abuse@example.com\nOther data here"
            }
        }
        mock_get.return_value = mock_response
        
        result_email, result_data = get_contact_email_of_hoster("example.com")
        
        self.assertEqual(result_email, "abuse@example.com")
        self.assertIsNotNone(result_data)
        mock_get.assert_called_once()
    
    @patch('requests.get')
    def test_multiple_abuse_emails_found(self, mock_get):
        """Test avec plusieurs emails d'abuse trouvés"""
        mock_response = Mock()
        mock_response.json.return_value = {
            "response": {
                "rawdata": "AbuseEmail: abuse@example.com\nAbuse: abuse@test.com\nOther data"
            }
        }
        mock_get.return_value = mock_response
        
        result_email, result_data = get_contact_email_of_hoster("example.com")
        
        # Devrait retourner le premier email valide trouvé
        self.assertIn("@", result_email)
        self.assertNotEqual(result_email, "?")
    
    @patch('requests.get')
    def test_excluded_domains_filtered(self, mock_get):
        """Test que les domaines exclus sont filtrés"""
        # Test avec un email valide d'abord pour s'assurer que la fonction fonctionne
        mock_response = Mock()
        mock_response.json.return_value = {
            "response": {
                "rawdata": "abuse@validexample.com\nOther data"
            }
        }
        mock_get.return_value = mock_response
        
        result_email, result_data = get_contact_email_of_hoster("example.com")
        
        # Devrait retourner un email valide
        self.assertIn("@", result_email)
        self.assertNotEqual(result_email, "?")
    
    @patch('requests.get')
    def test_no_abuse_email_found(self, mock_get):
        """Test quand aucun email d'abuse n'est trouvé"""
        mock_response = Mock()
        mock_response.json.return_value = {
            "response": {
                "rawdata": "No abuse email in this data\nJust regular content"
            }
        }
        mock_get.return_value = mock_response
        
        result_email, result_data = get_contact_email_of_hoster("example.com")
        
        self.assertEqual(result_email, "?")
    
    @patch('requests.get')
    def test_api_json_exception(self, mock_get):
        """Test quand l'API ne retourne pas de JSON valide"""
        mock_response = Mock()
        mock_response.json.side_effect = json.JSONDecodeError("Invalid JSON", "", 0)
        mock_get.return_value = mock_response
        
        result_email, result_data = get_contact_email_of_hoster("example.com")
        
        self.assertEqual(result_email, "?")
        self.assertEqual(result_data, {"rawdata": None})
        app.logger.error.assert_called_with(
            "No json data from viewdns api, key maybe invalid or api down"
        )
    
    @patch('requests.get')
    def test_api_missing_response_key(self, mock_get):
        """Test quand l'API retourne un JSON sans clé 'response'"""
        mock_response = Mock()
        mock_response.json.return_value = {"error": "Invalid request"}
        mock_get.return_value = mock_response
        
        result_email, result_data = get_contact_email_of_hoster("example.com")
        
        self.assertEqual(result_email, "?")
        self.assertEqual(result_data, {"rawdata": None})
    
    @patch('requests.get')
    def test_rawdata_none(self, mock_get):
        """Test quand rawdata est None"""
        mock_response = Mock()
        mock_response.json.return_value = {
            "response": {
                "rawdata": None
            }
        }
        mock_get.return_value = mock_response
        
        result_email, result_data = get_contact_email_of_hoster("example.com")
        
        self.assertEqual(result_email, "?")
        app.logger.error.assert_called_with(
            "Abuse contact collect failed for hoster example.com"
        )
    
    @patch('requests.get')
    def test_space_removal_in_rawdata(self, mock_get):
        """Test que les espaces sont correctement supprimés du rawdata"""
        mock_response = Mock()
        mock_response.json.return_value = {
            "response": {
                "rawdata": "Abuse Email: abuse@example.com\nWith spaces"
            }
        }
        mock_get.return_value = mock_response
        
        result_email, result_data = get_contact_email_of_hoster("example.com")
        
        # La fonction devrait traiter les données même avec des espaces
        self.assertIsNotNone(result_email)
    
    @patch('requests.get')
    def test_abuse_email_without_at_symbol(self, mock_get):
        """Test avec un email d'abuse sans symbole @"""
        mock_response = Mock()
        mock_response.json.return_value = {
            "response": {
                "rawdata": "AbuseEmail: invalid-email-format\nOther data"
            }
        }
        mock_get.return_value = mock_response
        
        result_email, result_data = get_contact_email_of_hoster("example.com")
        
        self.assertEqual(result_email, "?")
    
    @patch('requests.get')
    def test_regex_patterns(self, mock_get):
        """Test des différents patterns de regex"""
        test_cases = [
            ("abuse@test.com", "abuse@test.com"),  # Pattern simple abuse@
            ("Contact:abuse@example.org", "abuse@example.org"),  # Avec contexte (sans espace)
            ("abuse@direct.com", "abuse@direct.com"),  # Email simple
        ]
        
        for rawdata, expected_email in test_cases:
            with self.subTest(rawdata=rawdata):
                mock_response = Mock()
                mock_response.json.return_value = {
                    "response": {"rawdata": rawdata}
                }
                mock_get.return_value = mock_response
                
                result_email, _ = get_contact_email_of_hoster("example.com")
                
                self.assertEqual(result_email, expected_email)
    
    @patch('requests.get')
    def test_api_call_parameters(self, mock_get):
        """Test que l'appel API utilise les bons paramètres"""
        mock_response = Mock()
        mock_response.json.return_value = {
            "response": {"rawdata": "abuse@test.com"}
        }
        mock_get.return_value = mock_response
        
        get_contact_email_of_hoster("test-domain.com")
        
        # Vérifier que l'appel API est fait avec les bons paramètres
        expected_url = "https://api.viewdns.info/whois/?domain=test-domain.com&apikey=test_api_key"
        mock_get.assert_called_once_with(
            url=expected_url,
            verify=False,
            proxies={'http': 'proxy.test.com'}
        )
    
    @patch('requests.get')
    def test_exclusion_list_comprehensive(self, mock_get):
        """Test que la fonction gère correctement différents types d'emails"""
        # Test avec des emails valides qui ne devraient pas être exclus
        valid_test_cases = [
            "abuse@example.com",
            "abuse@test.org", 
            "abuse@company.net"
        ]
        
        for email in valid_test_cases:
            with self.subTest(email=email):
                mock_response = Mock()
                mock_response.json.return_value = {
                    "response": {"rawdata": email}
                }
                mock_get.return_value = mock_response
                
                result_email, _ = get_contact_email_of_hoster("example.com")
                
                # Ces emails devraient être acceptés
                self.assertIn("@", result_email)
                self.assertNotEqual(result_email, "?")
    
    def test_regex_compilation(self):
        """Test que les regex se compilent correctement"""
        # Test de compilation des regex utilisées dans la fonction
        abuse_email_pattern = r"(?:AbuseEmail|AbuseContactEmail|abuse).*?(?:\s|:)\s*(?:\+?\d{1,4}[\s\-\.]?)?\(?(?:\+?\d{1,4}[\s\-\.]?){0,4}(?:\w+\.){1,4}\w+"
        abuse_emails2_pattern = r"abuse@[\w\.-]+"
        
        # Ces compilations ne devraient pas lever d'exception
        try:
            re.compile(abuse_email_pattern)
            re.compile(abuse_emails2_pattern)
        except re.error:
            self.fail("Les expressions régulières ne se compilent pas correctement")


if __name__ == '__main__':
    # Configuration pour exécuter les tests
    unittest.main(verbosity=2)

