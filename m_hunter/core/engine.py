from m_hunter.core.scan import Scan
from m_hunter.core.target import Target


class ScanEngine:
    def create_scan(self, target_url: str) -> Scan:
        target = Target(target_url)
        return Scan(target)

    def start_scan(self, target_url: str) -> Scan:
        scan = self.create_scan(target_url)
        scan.start()
        return scan

    def finish_scan(self, scan: Scan) -> None:
        scan.finish()
