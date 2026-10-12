import sys, unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"src"))
from analyze_email import analyze, parse_email, url_flags
ROOT=Path(__file__).resolve().parents[1]
class Tests(unittest.TestCase):
 def test_phishing_scores_higher(self):
  p=analyze(parse_email(ROOT/"data/sample_phishing.eml"))
  l=analyze(parse_email(ROOT/"data/sample_legitimate.eml"))
  self.assertGreater(p["risk_score"],l["risk_score"])
  self.assertIn("reply_to_domain_mismatch",p["findings"])
 def test_ip_literal(self):
  self.assertIn("ip_literal_url_host",url_flags("http://192.0.2.5/login"))
 def test_url_extraction_does_not_visit(self):
  p=parse_email(ROOT/"data/sample_phishing.eml")
  self.assertTrue(p["urls"]); self.assertIn("192.0.2.45",p["urls"][0])
if __name__=="__main__": unittest.main()
