#!/usr/bin/env python3
"""
Tests pour la version épurée du script d'extraction de domaines avec tldextract uniquement.
"""

import unittest
from domain_extractor_tldextract import (
    DomainExtractionServiceFactory,
    TldExtractDomainExtractor,
    TldExtractDomainValidator,
    TldExtractDomainParser,
    TextProcessor,
    ResultFormatter,
    DomainType
)


class TestTldExtractDomainExtractor(unittest.TestCase):
    """Tests pour l'extracteur tldextract."""
    
    def setUp(self):
        self.extractor = TldExtractDomainExtractor()
    
    def test_extract_simple_domains(self):
        """Test d'extraction de domaines simples."""
        text = "Visitez google.com et github.com"
        domains = self.extractor.extract_domains(text)
        self.assertIn("google.com", domains)
        self.assertIn("github.com", domains)
    
    def test_extract_github_pages(self):
        """Test d'extraction de pages GitHub."""
        text = "Projet sur username.github.io"
        domains = self.extractor.extract_domains(text)
        self.assertIn("username.github.io", domains)
    
    def test_extract_complex_tlds(self):
        """Test d'extraction avec TLD complexes."""
        text = "Sites: example.co.uk et test.com.au"
        domains = self.extractor.extract_domains(text)
        self.assertIn("example.co.uk", domains)
    
    def test_extract_subdomains(self):
        """Test d'extraction de sous-domaines."""
        text = "API sur api.service.fr et docs sur docs.python.org"
        domains = self.extractor.extract_domains(text)
        self.assertIn("api.service.fr", domains)
        self.assertIn("docs.python.org", domains)
    
    def test_extract_with_protocols(self):
        """Test d'extraction avec protocoles."""
        text = "Visitez https://www.example.com et http://test.org"
        domains = self.extractor.extract_domains(text)
        self.assertIn("example.com", domains)
        self.assertIn("test.org", domains)
    
    def test_extract_no_domains(self):
        """Test sans domaines."""
        text = "Texte sans aucun domaine valide"
        domains = self.extractor.extract_domains(text)
        self.assertEqual(len(domains), 0)


class TestTldExtractDomainValidator(unittest.TestCase):
    """Tests pour le validateur tldextract."""
    
    def setUp(self):
        self.validator = TldExtractDomainValidator()
    
    def test_valid_simple_domains(self):
        """Test de domaines simples valides."""
        valid_domains = [
            "google.com",
            "github.com",
            "example.org"
        ]
        for domain in valid_domains:
            with self.subTest(domain=domain):
                self.assertTrue(self.validator.is_valid_domain(domain))
    
    def test_valid_github_pages(self):
        """Test de validation des pages GitHub."""
        self.assertTrue(self.validator.is_valid_domain("username.github.io"))
    
    def test_valid_complex_tlds(self):
        """Test de validation avec TLD complexes."""
        valid_domains = [
            "example.co.uk",
            "test.com.au",
            "site.org.uk"
        ]
        for domain in valid_domains:
            with self.subTest(domain=domain):
                self.assertTrue(self.validator.is_valid_domain(domain))
    
    def test_valid_subdomains(self):
        """Test de validation de sous-domaines."""
        valid_domains = [
            "api.service.fr",
            "docs.python.org",
            "cdn.jsdelivr.net"
        ]
        for domain in valid_domains:
            with self.subTest(domain=domain):
                self.assertTrue(self.validator.is_valid_domain(domain))
    
    def test_invalid_domains(self):
        """Test de domaines invalides."""
        invalid_domains = [
            "",
            "invalid",
            ".com",
            "test.",
            "test..com"
        ]
        for domain in invalid_domains:
            with self.subTest(domain=domain):
                self.assertFalse(self.validator.is_valid_domain(domain))
    
    def test_domain_too_long(self):
        """Test de domaine trop long."""
        long_domain = "a" * 250 + ".com"
        self.assertFalse(self.validator.is_valid_domain(long_domain))


class TestTldExtractDomainParser(unittest.TestCase):
    """Tests pour l'analyseur tldextract."""
    
    def setUp(self):
        self.parser = TldExtractDomainParser()
    
    def test_parse_simple_domain(self):
        """Test d'analyse de domaine simple."""
        domain_info = self.parser.parse_domain("google.com", 0)
        self.assertEqual(domain_info.full_domain, "google.com")
        self.assertEqual(domain_info.domain, "google")
        self.assertEqual(domain_info.tld, "com")
        self.assertIsNone(domain_info.subdomain)
        self.assertEqual(domain_info.domain_type, DomainType.DOMAIN)
    
    def test_parse_github_pages(self):
        """Test d'analyse des pages GitHub."""
        domain_info = self.parser.parse_domain("username.github.io", 0)
        self.assertEqual(domain_info.domain, "username")
        self.assertEqual(domain_info.tld, "github.io")
        self.assertIsNone(domain_info.subdomain)
        self.assertEqual(domain_info.domain_type, DomainType.DOMAIN)
    
    def test_parse_complex_tld(self):
        """Test d'analyse avec TLD complexe."""
        domain_info = self.parser.parse_domain("example.co.uk", 0)
        self.assertEqual(domain_info.domain, "example")
        self.assertEqual(domain_info.tld, "co.uk")
        self.assertIsNone(domain_info.subdomain)
    
    def test_parse_subdomain(self):
        """Test d'analyse de sous-domaine."""
        domain_info = self.parser.parse_domain("api.service.fr", 0)
        self.assertEqual(domain_info.full_domain, "api.service.fr")
        self.assertEqual(domain_info.subdomain, "api")
        self.assertEqual(domain_info.domain, "service")
        self.assertEqual(domain_info.tld, "fr")
        self.assertEqual(domain_info.domain_type, DomainType.SUBDOMAIN)
    
    def test_parse_subdomain_with_complex_tld(self):
        """Test d'analyse de sous-domaine avec TLD complexe."""
        domain_info = self.parser.parse_domain("api.company.co.uk", 0)
        self.assertEqual(domain_info.subdomain, "api")
        self.assertEqual(domain_info.domain, "company")
        self.assertEqual(domain_info.tld, "co.uk")
        self.assertEqual(domain_info.domain_type, DomainType.SUBDOMAIN)
    
    def test_parse_multiple_subdomains(self):
        """Test d'analyse avec plusieurs sous-domaines."""
        domain_info = self.parser.parse_domain("test.dev.mysite.net", 0)
        self.assertEqual(domain_info.subdomain, "test.dev")
        self.assertEqual(domain_info.domain, "mysite")
        self.assertEqual(domain_info.tld, "net")


class TestTextProcessor(unittest.TestCase):
    """Tests pour le processeur de texte."""
    
    def setUp(self):
        self.processor = TextProcessor()
    
    def test_clean_text_normal(self):
        """Test du nettoyage de texte normal."""
        text = "Voici un texte avec des domaines: google.com et github.com"
        result = self.processor.clean_text(text)
        self.assertEqual(result, text)
    
    def test_clean_text_with_control_chars(self):
        """Test du nettoyage avec caractères de contrôle."""
        text = "Texte\x00avec\x1fcaractères\x7fde\x9fcontrôle"
        result = self.processor.clean_text(text)
        self.assertEqual(result, "Texte avec caractères de contrôle")
    
    def test_clean_text_empty(self):
        """Test avec texte vide."""
        result = self.processor.clean_text("")
        self.assertEqual(result, "")


class TestResultFormatter(unittest.TestCase):
    """Tests pour le formateur de résultats."""
    
    def setUp(self):
        self.formatter = ResultFormatter()
    
    def test_format_empty_results(self):
        """Test de formatage avec résultats vides."""
        results = self.formatter.format_results([])
        self.assertEqual(results['total_domains'], 0)
        self.assertEqual(len(results['domains']), 0)
        self.assertEqual(len(results['subdomains']), 0)
        self.assertEqual(results['summary']['extraction_method'], 'tldextract')
    
    def test_format_mixed_results(self):
        """Test de formatage avec domaines et sous-domaines."""
        from domain_extractor_tldextract import DomainInfo, DomainType
        
        domain_infos = [
            DomainInfo("google.com", None, "google", "com", DomainType.DOMAIN, 0),
            DomainInfo("api.service.fr", "api", "service", "fr", DomainType.SUBDOMAIN, 1)
        ]
        results = self.formatter.format_results(domain_infos)
        
        self.assertEqual(results['total_domains'], 2)
        self.assertEqual(len(results['domains']), 1)
        self.assertEqual(len(results['subdomains']), 1)
        self.assertEqual(results['summary']['total_domains'], 1)
        self.assertEqual(results['summary']['total_subdomains'], 1)
        self.assertEqual(results['summary']['extraction_method'], 'tldextract')


class TestDomainExtractionService(unittest.TestCase):
    """Tests pour le service principal."""
    
    def setUp(self):
        self.service = DomainExtractionServiceFactory.create_default_service()
    
    def test_service_creation(self):
        """Test de création du service."""
        self.assertIsNotNone(self.service)
    
    def test_extract_domains_workflow(self):
        """Test du workflow complet d'extraction."""
        text = "Visitez google.com et api.service.fr"
        results = self.service.extract_domains_from_text(text)
        
        self.assertIsInstance(results, dict)
        self.assertIn('total_domains', results)
        self.assertIn('domains', results)
        self.assertIn('subdomains', results)
        self.assertIn('summary', results)
        self.assertEqual(results['summary']['extraction_method'], 'tldextract')
        self.assertGreater(results['total_domains'], 0)


class TestRealWorldScenarios(unittest.TestCase):
    """Tests avec des scénarios du monde réel."""
    
    def setUp(self):
        self.service = DomainExtractionServiceFactory.create_default_service()
    
    def test_github_ecosystem(self):
        """Test avec l'écosystème GitHub."""
        text = """
        Ressources GitHub :
        - Dépôt principal : github.com/user/repo
        - Pages du projet : user.github.io/project
        - API GitHub : api.github.com/repos/user/repo
        - CDN : cdn.jsdelivr.net/gh/user/repo
        """
        
        results = self.service.extract_domains_from_text(text)
        self.assertGreater(results['total_domains'], 2)
        
        # Vérifie la présence de domaines GitHub
        all_domains = [d['full_domain'] for d in results['domains'] + results['subdomains']]
        self.assertTrue(any('github.com' in domain for domain in all_domains))
        self.assertTrue(any('github.io' in domain for domain in all_domains))
    
    def test_international_domains(self):
        """Test avec domaines internationaux."""
        text = """
        Sites internationaux :
        - Allemagne : münchen.de
        - France : société.fr
        - Royaume-Uni : company.co.uk
        """
        
        results = self.service.extract_domains_from_text(text)
        self.assertGreater(results['total_domains'], 0)
        
        # Vérifie la présence de TLD internationaux
        tlds = results['unique_tlds']
        self.assertTrue(any(tld in ['de', 'fr', 'co.uk'] for tld in tlds))
    
    def test_complex_subdomains(self):
        """Test avec sous-domaines complexes."""
        text = """
        Infrastructure :
        - API de production : api.prod.service.com
        - API de staging : api.staging.service.com
        - Documentation : docs.service.com
        - CDN : cdn.service.com
        """
        
        results = self.service.extract_domains_from_text(text)
        self.assertGreaterEqual(results['summary']['total_subdomains'], 2)
    
    def test_mixed_content_comprehensive(self):
        """Test avec contenu mixte complet."""
        text = """
        Ressources de développement :
        
        Hébergement et services :
        - Site principal : https://www.company.co.uk
        - API REST : api.company.co.uk/v1/
        - Documentation : docs.company.co.uk
        
        Outils de développement :
        - Dépôt GitHub : github.com/company/project
        - Pages GitHub : company.github.io
        - NPM Registry : npmjs.com/package/project
        - CDN : cdn.jsdelivr.net/npm/project
        
        Monitoring et analytics :
        - Monitoring : monitoring.service.fr
        - Analytics : analytics.service.fr
        """
        
        results = self.service.extract_domains_from_text(text)
        
        # Doit trouver plusieurs domaines et sous-domaines
        self.assertGreater(results['total_domains'], 5)
        self.assertGreater(results['summary']['total_subdomains'], 3)
        
        # Doit identifier plusieurs TLD différents
        self.assertGreater(results['summary']['unique_tlds_count'], 3)
        
        # Vérifie la méthode d'extraction
        self.assertEqual(results['summary']['extraction_method'], 'tldextract')


def run_tldextract_tests():
    """Exécute tous les tests de la version tldextract."""
    print("=== TESTS DE LA VERSION TLDEXTRACT UNIQUEMENT ===\n")
    
    # Crée la suite de tests
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    # Ajoute toutes les classes de test
    test_classes = [
        TestTldExtractDomainExtractor,
        TestTldExtractDomainValidator,
        TestTldExtractDomainParser,
        TestTextProcessor,
        TestResultFormatter,
        TestDomainExtractionService,
        TestRealWorldScenarios
    ]
    
    for test_class in test_classes:
        tests = loader.loadTestsFromTestCase(test_class)
        suite.addTests(tests)
    
    # Exécute les tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    # Résumé
    print(f"\n=== RÉSUMÉ DES TESTS TLDEXTRACT ===")
    print(f"Tests exécutés: {result.testsRun}")
    print(f"Échecs: {len(result.failures)}")
    print(f"Erreurs: {len(result.errors)}")
    print(f"Succès: {result.testsRun - len(result.failures) - len(result.errors)}")
    
    if result.failures:
        print("\nÉCHECS:")
        for test, traceback in result.failures:
            print(f"  - {test}")
    
    if result.errors:
        print("\nERREURS:")
        for test, traceback in result.errors:
            print(f"  - {test}")
    
    return result.wasSuccessful()


if __name__ == "__main__":
    success = run_tldextract_tests()
    exit(0 if success else 1)

