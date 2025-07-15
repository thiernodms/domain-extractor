"""
Tests unitaires complets pour le module de détection de domaines.

Ce fichier contient tous les tests unitaires pour valider le comportement
de chaque classe et méthode du module domain_detection.
"""

import unittest
from unittest.mock import patch, MagicMock
from domain_detection import (
    TextDomainExtractor,
    StandardURLTransformer,
    DomainDetectionModule,
    extract_urls_from_text
)


class TestTextDomainExtractor(unittest.TestCase):
    """Tests unitaires pour la classe TextDomainExtractor."""
    
    def setUp(self):
        """Initialisation avant chaque test."""
        self.extractor = TextDomainExtractor()
    
    def test_extract_domains_empty_text(self):
        """Test avec un texte vide."""
        result = self.extractor.extract_domains("")
        self.assertEqual(result, [])
    
    def test_extract_domains_none_text(self):
        """Test avec None."""
        result = self.extractor.extract_domains(None)
        self.assertEqual(result, [])
    
    def test_extract_domains_no_domains(self):
        """Test avec un texte sans domaines."""
        text = "Ceci est un texte sans aucun domaine valide."
        result = self.extractor.extract_domains(text)
        self.assertEqual(result, [])
    
    def test_extract_domains_single_domain(self):
        """Test avec un seul domaine."""
        text = "Visitez example.com pour plus d'informations."
        result = self.extractor.extract_domains(text)
        self.assertIn("example.com", result)
        self.assertEqual(len(result), 1)
    
    def test_extract_domains_multiple_domains(self):
        """Test avec plusieurs domaines."""
        text = "Visitez example.com et google.com et github.io"
        result = self.extractor.extract_domains(text)
        expected_domains = ["example.com", "google.com", "github.io"]
        for domain in expected_domains:
            self.assertIn(domain, result)
        self.assertEqual(len(result), 3)
    
    def test_extract_domains_with_subdomains(self):
        """Test avec des sous-domaines."""
        text = "API sur api.example.com et docs sur docs.example.org"
        result = self.extractor.extract_domains(text)
        expected_domains = ["api.example.com", "docs.example.org"]
        for domain in expected_domains:
            self.assertIn(domain, result)
    
    def test_extract_domains_complex_subdomains(self):
        """Test avec des sous-domaines complexes."""
        text = "Serveur test.staging.app.example.com"
        result = self.extractor.extract_domains(text)
        self.assertIn("test.staging.app.example.com", result)
    
    def test_extract_domains_duplicate_removal(self):
        """Test de suppression des doublons."""
        text = "example.com et example.com et example.com"
        result = self.extractor.extract_domains(text)
        self.assertEqual(len(result), 1)
        self.assertIn("example.com", result)
    
    def test_extract_domains_with_www(self):
        """Test avec www."""
        text = "Site principal www.example.com"
        result = self.extractor.extract_domains(text)
        self.assertIn("www.example.com", result)
    
    def test_extract_domains_invalid_domains(self):
        """Test avec des domaines invalides."""
        text = "Domaines invalides: invalid..domain et .invalid et domain."
        result = self.extractor.extract_domains(text)
        # Les domaines invalides ne doivent pas être extraits
        self.assertEqual(len(result), 0)
    
    def test_validate_domains_with_mock(self):
        """Test de validation avec mock."""
        # Mock pour un domaine valide
        mock_extract = MagicMock()
        mock_extract.suffix = "com"
        mock_extract.domain = "example"
        mock_extract.subdomain = ""
        
        with patch('domain_detection.tldextract.extract', return_value=mock_extract):
            result = self.extractor._validate_domains(["example.com"])
            self.assertEqual(result, ["example.com"])


class TestStandardURLTransformer(unittest.TestCase):
    """Tests unitaires pour la classe StandardURLTransformer."""
    
    def setUp(self):
        """Initialisation avant chaque test."""
        self.transformer = StandardURLTransformer()
    
    def test_transform_to_urls_empty_list(self):
        """Test avec une liste vide."""
        result = self.transformer.transform_to_urls([])
        self.assertEqual(result, [])
    
    def test_transform_to_urls_none_list(self):
        """Test avec None."""
        result = self.transformer.transform_to_urls(None)
        self.assertEqual(result, [])
    
    def test_transform_to_urls_single_domain(self):
        """Test avec un seul domaine."""
        domains = ["example.com"]
        result = self.transformer.transform_to_urls(domains)
        self.assertEqual(result, ["https://example.com"])
    
    def test_transform_to_urls_multiple_domains(self):
        """Test avec plusieurs domaines."""
        domains = ["example.com", "google.com", "github.io"]
        result = self.transformer.transform_to_urls(domains)
        expected = ["https://example.com", "https://google.com", "https://github.io"]
        self.assertEqual(sorted(result), sorted(expected))
    
    def test_transform_to_urls_with_subdomains(self):
        """Test avec des sous-domaines."""
        domains = ["api.example.com", "docs.example.org"]
        result = self.transformer.transform_to_urls(domains)
        expected = ["https://api.example.com", "https://docs.example.org"]
        self.assertEqual(sorted(result), sorted(expected))
    
    def test_transform_to_urls_already_with_https(self):
        """Test avec des URLs déjà formées (HTTPS)."""
        domains = ["https://example.com"]
        result = self.transformer.transform_to_urls(domains)
        self.assertEqual(result, ["https://example.com"])
    
    def test_transform_to_urls_already_with_http(self):
        """Test avec des URLs déjà formées (HTTP)."""
        domains = ["http://example.com"]
        result = self.transformer.transform_to_urls(domains)
        self.assertEqual(result, ["http://example.com"])
    
    def test_custom_default_scheme(self):
        """Test avec un schéma par défaut personnalisé."""
        transformer = StandardURLTransformer(default_scheme="http")
        domains = ["example.com"]
        result = transformer.transform_to_urls(domains)
        self.assertEqual(result, ["http://example.com"])
    
    def test_create_url_without_scheme(self):
        """Test de création d'URL sans schéma."""
        url = self.transformer._create_url("example.com")
        self.assertEqual(url, "https://example.com")
    
    def test_create_url_with_scheme(self):
        """Test de création d'URL avec schéma existant."""
        url = self.transformer._create_url("http://example.com")
        self.assertEqual(url, "http://example.com")
    
    def test_is_valid_url_valid(self):
        """Test de validation d'URL valide."""
        self.assertTrue(self.transformer._is_valid_url("https://example.com"))
        self.assertTrue(self.transformer._is_valid_url("http://example.com"))
    
    def test_is_valid_url_invalid(self):
        """Test de validation d'URL invalide."""
        self.assertFalse(self.transformer._is_valid_url("invalid-url"))
        self.assertFalse(self.transformer._is_valid_url(""))
        self.assertFalse(self.transformer._is_valid_url("https://"))


class TestDomainDetectionModule(unittest.TestCase):
    """Tests unitaires pour la classe DomainDetectionModule."""
    
    def setUp(self):
        """Initialisation avant chaque test."""
        self.module = DomainDetectionModule()
    
    def test_process_text_empty(self):
        """Test avec un texte vide."""
        result = self.module.process_text("")
        self.assertEqual(result, [])
    
    def test_process_text_none(self):
        """Test avec None."""
        result = self.module.process_text(None)
        self.assertEqual(result, [])
    
    def test_process_text_no_domains(self):
        """Test avec un texte sans domaines."""
        text = "Ceci est un texte sans domaines."
        result = self.module.process_text(text)
        self.assertEqual(result, [])
    
    def test_process_text_single_domain(self):
        """Test avec un seul domaine."""
        text = "Visitez example.com"
        result = self.module.process_text(text)
        self.assertEqual(result, ["https://example.com"])
    
    def test_process_text_multiple_domains(self):
        """Test avec plusieurs domaines."""
        text = "Visitez example.com et google.com"
        result = self.module.process_text(text)
        expected = ["https://example.com", "https://google.com"]
        self.assertEqual(sorted(result), sorted(expected))
    
    def test_process_text_with_subdomains(self):
        """Test avec des sous-domaines."""
        text = "API: api.example.com, Docs: docs.example.org"
        result = self.module.process_text(text)
        expected = ["https://api.example.com", "https://docs.example.org"]
        self.assertEqual(sorted(result), sorted(expected))
    
    def test_custom_extractor_and_transformer(self):
        """Test avec extracteur et transformateur personnalisés."""
        mock_extractor = MagicMock()
        mock_extractor.extract_domains.return_value = ["example.com"]
        
        mock_transformer = MagicMock()
        mock_transformer.transform_to_urls.return_value = ["http://example.com"]
        
        module = DomainDetectionModule(mock_extractor, mock_transformer)
        result = module.process_text("test text")
        
        mock_extractor.extract_domains.assert_called_once_with("test text")
        mock_transformer.transform_to_urls.assert_called_once_with(["example.com"])
        self.assertEqual(result, ["http://example.com"])


class TestUtilityFunction(unittest.TestCase):
    """Tests unitaires pour la fonction utilitaire."""
    
    def test_extract_urls_from_text_basic(self):
        """Test de base de la fonction utilitaire."""
        text = "Visitez example.com et google.com"
        result = extract_urls_from_text(text)
        expected = ["https://example.com", "https://google.com"]
        self.assertEqual(sorted(result), sorted(expected))
    
    def test_extract_urls_from_text_empty(self):
        """Test avec texte vide."""
        result = extract_urls_from_text("")
        self.assertEqual(result, [])
    
    def test_extract_urls_from_text_complex(self):
        """Test avec un texte complexe."""
        text = """
        Documentation: docs.python.org
        API: api.github.com
        Blog: blog.example.fr
        """
        result = extract_urls_from_text(text)
        expected = [
            "https://docs.python.org",
            "https://api.github.com", 
            "https://blog.example.fr"
        ]
        self.assertEqual(sorted(result), sorted(expected))


class TestIntegration(unittest.TestCase):
    """Tests d'intégration pour le module complet."""
    
    def test_end_to_end_workflow(self):
        """Test du workflow complet de bout en bout."""
        text = """
        Pour votre projet, consultez:
        - Documentation: docs.example.com
        - API: api.v2.example.org  
        - Support: help.support.example.fr
        - Site principal: www.example.com
        """
        
        result = extract_urls_from_text(text)
        
        # Vérifier que tous les domaines sont détectés
        expected_domains = [
            "docs.example.com",
            "api.v2.example.org",
            "help.support.example.fr", 
            "www.example.com"
        ]
        
        for domain in expected_domains:
            expected_url = f"https://{domain}"
            self.assertIn(expected_url, result)
        
        # Vérifier qu'il n'y a pas de doublons
        self.assertEqual(len(result), len(set(result)))
    
    def test_real_world_scenario(self):
        """Test avec un scénario réel."""
        text = """
        Bonjour,
        
        Voici les liens importants pour notre projet:
        
        1. Site web principal: www.monentreprise.fr
        2. Documentation technique: docs.api.monentreprise.fr
        3. Interface d'administration: admin.backend.monentreprise.fr
        4. CDN pour les assets: cdn.static.monentreprise.fr
        5. Environnement de test: test.staging.monentreprise.fr
        
        Pour le support, contactez support@monentreprise.fr
        
        Cordialement
        """
        
        result = extract_urls_from_text(text)
        
        # Vérifier la présence des domaines attendus
        expected_urls = [
            "https://www.monentreprise.fr",
            "https://docs.api.monentreprise.fr",
            "https://admin.backend.monentreprise.fr",
            "https://cdn.static.monentreprise.fr",
            "https://test.staging.monentreprise.fr",
            "https://monentreprise.fr"  # Extrait de l'email
        ]
        
        for url in expected_urls:
            self.assertIn(url, result)


def run_tests():
    """Exécute tous les tests unitaires."""
    # Créer une suite de tests
    test_suite = unittest.TestSuite()
    
    # Ajouter toutes les classes de tests
    test_classes = [
        TestTextDomainExtractor,
        TestStandardURLTransformer,
        TestDomainDetectionModule,
        TestUtilityFunction,
        TestIntegration
    ]
    
    for test_class in test_classes:
        tests = unittest.TestLoader().loadTestsFromTestCase(test_class)
        test_suite.addTests(tests)
    
    # Exécuter les tests avec un rapport détaillé
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(test_suite)
    
    # Afficher un résumé
    print(f"\n{'='*60}")
    print(f"RÉSUMÉ DES TESTS")
    print(f"{'='*60}")
    print(f"Tests exécutés: {result.testsRun}")
    print(f"Échecs: {len(result.failures)}")
    print(f"Erreurs: {len(result.errors)}")
    print(f"Succès: {result.testsRun - len(result.failures) - len(result.errors)}")
    
    if result.failures:
        print(f"\nÉCHECS:")
        for test, traceback in result.failures:
            print(f"- {test}: {traceback}")
    
    if result.errors:
        print(f"\nERREURS:")
        for test, traceback in result.errors:
            print(f"- {test}: {traceback}")
    
    success_rate = ((result.testsRun - len(result.failures) - len(result.errors)) / result.testsRun) * 100
    print(f"\nTaux de réussite: {success_rate:.1f}%")
    
    return result.wasSuccessful()


if __name__ == "__main__":
    print("🧪 EXÉCUTION DES TESTS UNITAIRES")
    print("=" * 60)
    success = run_tests()
    
    if success:
        print("\n✅ Tous les tests sont passés avec succès!")
    else:
        print("\n❌ Certains tests ont échoué.")
        exit(1)

