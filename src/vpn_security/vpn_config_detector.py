import subprocess
import re
import platform
from typing import Dict, List, Optional

class VPNConfigDetector:
    """
    A comprehensive VPN configuration detection and analysis class.
    
    Supports detection of VPN connections across different platforms
    and provides security recommendations.
    """
    
    @staticmethod
    def detect_vpn_connections() -> List[Dict[str, str]]:
        """
        Detect active VPN connections based on the current operating system.
        
        Returns:
            List of dictionaries containing VPN connection details
        """
        os_name = platform.system().lower()
        
        try:
            if os_name == 'darwin':  # macOS
                return VPNConfigDetector._detect_macos_vpn()
            elif os_name == 'linux':
                return VPNConfigDetector._detect_linux_vpn()
            else:
                return []
        except Exception as e:
            print(f"Error detecting VPN connections: {e}")
            return []
    
    @staticmethod
    def _detect_macos_vpn() -> List[Dict[str, str]]:
        """Detect VPN connections on macOS"""
        try:
            result = subprocess.run(['scutil', '--nc', 'list'], 
                                    capture_output=True, text=True, timeout=5)
            vpn_connections = []
            for line in result.stdout.split('\n'):
                match = re.search(r'\((.*?)\)', line)
                if match:
                    vpn_connections.append({
                        'name': match.group(1),
                        'status': 'detected'
                    })
            return vpn_connections
        except Exception:
            return []
    
    @staticmethod
    def _detect_linux_vpn() -> List[Dict[str, str]]:
        """Detect VPN connections on Linux"""
        try:
            result = subprocess.run(['ip', 'tuntap'], 
                                    capture_output=True, text=True, timeout=5)
            vpn_connections = []
            for line in result.stdout.split('\n'):
                if 'tun' in line:
                    vpn_connections.append({
                        'name': line.split(':')[0],
                        'status': 'detected'
                    })
            return vpn_connections
        except Exception:
            return []
    
    @staticmethod
    def analyze_vpn_security(connection: Dict[str, str]) -> Dict[str, str]:
        """
        Perform security analysis on a VPN connection.
        
        Args:
            connection: A dictionary containing VPN connection details
        
        Returns:
            A dictionary of security recommendations
        """
        recommendations = {
            'encryption': 'Unable to determine',
            'protocol': 'Unable to determine',
            'security_level': 'Low'
        }
        
        # Placeholder for more advanced security checks
        # In a real-world scenario, this would involve more comprehensive checks
        
        return recommendations