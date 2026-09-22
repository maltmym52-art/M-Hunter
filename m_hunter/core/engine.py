from m_hunter.core.finding import Finding
from m_hunter.core.scan import Scan
from m_hunter.core.target import Target
from m_hunter.scanners.base import BaseScanner


class ScanEngine:
    def create_scan(self, target_url: str) -> Scan:
        target = Target(target_url)
        return Scan(target)

    def start_scan(self, target_url: str) -> Scan:
        scan = self.create_scan(target_url)
        scan.start()
        return scan

    def run_scanners(
        self,
        scan: Scan,
        scanners: list[BaseScanner],
    ) -> list[Finding]:
        findings: list[Finding] = []

        for scanner in scanners:
            scanner_findings = scanner.run(scan.target)
            findings.extend(scanner_findings)

        return findings

    def finish_scan(self, scan: Scan) -> None:
        scan.finish()
